package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
)

type DnsRequest struct {
	LogContext log.Context
	LocalAddr  netip.AddrPort
	RemoteAddr netip.AddrPort
	Conn       *net.UDPConn
	Message    *fastdns.Message
	Domain     string
	QType      string
}

type DnsHandler struct {
	Config    DnsConfig
	Functions template.FuncMap
	Logger    log.Logger

	policy *template.Template
	dialer *fastdns.HTTPDialer
}

var drPool = sync.Pool{
	New: func() interface{} {
		r := new(DnsRequest)
		r.Message = fastdns.AcquireMessage()
		return r
	},
}

func (h *DnsHandler) Load() error {
	if len(h.Config.Listen) != 1 {
		return fmt.Errorf("invaild length of listen: %#v", h.Config.Listen)
	}
	if !strings.HasPrefix(h.Config.ProxyPass, "https://") {
		return fmt.Errorf("unsupported proxy_pass scheme: %#v", h.Config.ProxyPass)
	}

	endpoint, err := url.Parse(h.Config.ProxyPass)
	if err != nil {
		return fmt.Errorf("invaild dns server: %#v: %w", h.Config.ProxyPass, err)
	}

	if s := h.Config.Policy; s != "" && s != "proxy_pass" {
		h.policy, err = template.New(s).Funcs(h.Functions).Parse(s)
		if err != nil {
			return fmt.Errorf("invaild dns policy: %#v: %w", s, err)
		}
	}

	h.dialer = &fastdns.HTTPDialer{
		Endpoint: endpoint,
		Header: http.Header{
			"content-type": {"application/dns-message"},
			"user-agent":   {"liner/" + version},
		},
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				NextProtos:         []string{"h2"},
				InsecureSkipVerify: false,
				ServerName:         endpoint.Hostname(),
				ClientSessionCache: tls.NewLRUClientSessionCache(1024),
			},
		},
	}

	return nil
}

func (h *DnsHandler) Serve(ctx context.Context, conn *net.UDPConn) {
	defer conn.Close()

	laddr, _ := netip.ParseAddrPort(conn.LocalAddr().String())

	for {
		req := drPool.Get().(*DnsRequest)
		req.LocalAddr = laddr
		req.Conn = conn

		req.Message.Raw = req.Message.Raw[:cap(req.Message.Raw)]
		n, addr, err := req.Conn.ReadFromUDPAddrPort(req.Message.Raw)
		if err != nil {
			log.Error().Err(err).NetIPAddrPort("local_addr", req.LocalAddr).NetIPAddr("remote_addr", req.RemoteAddr.Addr()).Msg("dns read from error")
			continue
		}
		req.RemoteAddr = addr
		req.Message.Raw = req.Message.Raw[:n]
		req.Domain = ""
		req.QType = ""

		go h.ServeDNS(ctx, req)
	}
}

func (h *DnsHandler) ServeDNS(ctx context.Context, req *DnsRequest) {
	defer drPool.Put(req)

	req.LogContext = log.NewContext(req.LogContext[:0]).Xid("trace_id", log.NewXID()).NetIPAddrPort("local_addr", req.LocalAddr).NetIPAddr("remote_addr", req.RemoteAddr.Addr()).Value()

	if h.policy != nil {
		err := fastdns.ParseMessage(req.Message, req.Message.Raw, false)
		if err != nil {
			h.Logger.Error().Err(err).Msg("dns parse message error")
			return
		}

		req.Domain = b2s(AppendToLower(make([]byte, 0, 256), b2s(req.Message.Domain)))
		req.QType = req.Message.Question.Type.String()

		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)

		bb.Reset()
		err = h.policy.Execute(bb, struct {
			Request *DnsRequest
		}{req})
		if err != nil {
			h.Logger.Error().Err(err).Context(req.LogContext).Msg("dns execute policy error")
			return
		}

		policyName := strings.TrimSpace(bb.String())
		h.Logger.Debug().Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).Str("forward_policy_name", policyName).Msg("execute forward_policy ok")

		toaddrs := func(dst []netip.Addr, ss []string) []netip.Addr {
			for _, s := range ss {
				if addr, err := netip.ParseAddr(s); err == nil {
					dst = append(dst, addr)
				}
			}
			return dst
		}

		rw := DnsResponseWriter{req}
		parts := strings.Fields(policyName)
		switch parts[0] {
		case "ERROR", "error":
			if len(parts) != 2 {
				fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
				return
			}
			rcode, err := fastdns.ParseRcode(parts[1])
			if err != nil {
				h.Logger.Error().Err(err).Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).Msg("dns policy parse rcode error")
				fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
				return
			}
			h.Logger.Debug().Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).Stringer("rcode", rcode).Msg("dns policy error executed")
			fastdns.Error(rw, req.Message, rcode)
			return
		case "HOST", "host":
			addrs := toaddrs(make([]netip.Addr, 0, 4), parts[1:])
			h.Logger.Debug().Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).NetIPAddrs("hosts", addrs).Msg("dns policy host executed")
			fastdns.HOST(rw, req.Message, 300, addrs)
			return
		case "CNAME", "cname":
			if len(parts) != 2 {
				fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
				return
			}
			cnames := strings.Split(parts[1], ",")
			h.Logger.Debug().Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).Strs("cnames", cnames).Msg("dns policy cname executed")
			fastdns.CNAME(rw, req.Message, 300, cnames, nil)
			return
		case "TXT", "txt":
			if len(parts) != 2 {
				fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
				return
			}
			txt := parts[1]
			h.Logger.Debug().Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).Str("txt", txt).Msg("dns policy txt executed")
			fastdns.TXT(rw, req.Message, 300, txt)
			return
		}
	}

	conn, err := h.dialer.DialContext(ctx, "", "")
	if err != nil {
		h.Logger.Error().Err(err).Context(req.LogContext).Str("proxy_pass", h.Config.ProxyPass).Msg("dns dial error")
		return
	}
	defer h.dialer.Put(conn)

	_, err = conn.Write(req.Message.Raw)
	if err != nil {
		h.Logger.Error().Err(err).Context(req.LogContext).Str("proxy_pass", h.Config.ProxyPass).Msg("dns dial error")
		return
	}

	req.Message.Raw = req.Message.Raw[:cap(req.Message.Raw)]
	n, err := conn.Read(req.Message.Raw)
	if err != nil {
		h.Logger.Error().Err(err).Context(req.LogContext).Str("proxy_pass", h.Config.ProxyPass).Msg("dns read raw data error")
		return
	}
	req.Message.Raw = req.Message.Raw[:n]

	req.Conn.WriteToUDPAddrPort(req.Message.Raw, req.RemoteAddr)
}

type DnsResponseWriter struct {
	*DnsRequest
}

func (w DnsResponseWriter) LocalAddr() netip.AddrPort {
	return w.DnsRequest.LocalAddr
}

func (w DnsResponseWriter) RemoteAddr() netip.AddrPort {
	return w.DnsRequest.RemoteAddr
}

func (w DnsResponseWriter) Write(b []byte) (int, error) {
	return w.DnsRequest.Conn.WriteToUDPAddrPort(b, w.DnsRequest.RemoteAddr)
}

var _ fastdns.ResponseWriter = DnsResponseWriter{}
