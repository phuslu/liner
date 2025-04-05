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
	TraceID    log.XID
	LocalAddr  netip.AddrPort
	RemoteAddr netip.AddrPort
	Conn       *net.UDPConn
	Message    *fastdns.Message
}

type DnsHandler struct {
	Config    DnsConfig
	Functions template.FuncMap
	Logger    *log.CategorizedLogger

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
			log.Error().Err(err).Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Msg("dns read from error")
			continue
		}
		req.Message.Raw = req.Message.Raw[:n]
		req.RemoteAddr = addr
		req.TraceID = log.NewXID()

		go h.ServeDNS(ctx, req)
	}
}

func (h *DnsHandler) ServeDNS(ctx context.Context, req *DnsRequest) {
	defer drPool.Put(req)

	if h.policy != nil {
		err := fastdns.ParseMessage(req.Message, req.Message.Raw, false)
		if err != nil {
			h.Logger.Error().Err(err).Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Str("remote_url", h.Config.ProxyPass).Msg("dns parse message error")
			return
		}

		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)

		bb.Reset()
		err = h.policy.Execute(bb, struct {
			Request *DnsRequest
		}{req})
		if err != nil {
			h.Logger.Error().Err(err).Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Str("remote_url", h.Config.ProxyPass).Msg("dns execute policy error")
			return
		}

		policyName := strings.TrimSpace(bb.String())
		h.Logger.Debug().Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Uint16("req_msg_id", req.Message.Header.ID).Bytes("req_domain", req.Message.Domain).Str("forward_policy_name", policyName).Msg("execute forward_policy ok")

		parts := strings.Fields(policyName)
		switch parts[0] {
		case "error":
			rcode, err := fastdns.ParseRcode(parts[1])
			if err != nil {
				h.Logger.Error().Err(err).Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Uint16("req_msg_id", req.Message.Header.ID).Bytes("req_msg_domain", req.Message.Domain).Msg("dns policy parse rcode error")
				rcode = fastdns.RcodeRefused
			}
			h.Logger.Debug().Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Uint16("req_msg_id", req.Message.Header.ID).Bytes("req_msg_domain", req.Message.Domain).Stringer("rcode", rcode).Msg("dns policy execute host")
			req.Message.SetResponseHeader(rcode, 0)
			req.Conn.WriteToUDPAddrPort(req.Message.Raw, req.RemoteAddr)
			return
		case "host":
			addrs := make([]netip.Addr, 0, 4)
			for _, s := range parts[1:] {
				if addr, err := netip.ParseAddr(s); err == nil {
					addrs = append(addrs, addr)
				}
			}
			h.Logger.Debug().Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Uint16("req_msg_id", req.Message.Header.ID).Bytes("req_msg_domain", req.Message.Domain).NetIPAddrs("hosts", addrs).Msg("dns policy execute host")
			req.Message.SetResponseHeader(fastdns.RcodeNoError, uint16(len(addrs)))
			req.Message.Raw = fastdns.AppendHOSTRecord(req.Message.Raw, req.Message, 300, addrs)
			req.Conn.WriteToUDPAddrPort(req.Message.Raw, req.RemoteAddr)
			return
		}
	}

	conn, err := h.dialer.DialContext(ctx, "", "")
	if err != nil {
		h.Logger.Error().Err(err).Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Str("remote_url", h.Config.ProxyPass).Msg("dns dial error")
		return
	}
	defer h.dialer.Put(conn)

	_, err = conn.Write(req.Message.Raw)
	if err != nil {
		h.Logger.Error().Err(err).Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Str("remote_url", h.Config.ProxyPass).Msg("dns dial error")
		return
	}

	req.Message.Raw = req.Message.Raw[:cap(req.Message.Raw)]
	n, err := conn.Read(req.Message.Raw)
	if err != nil {
		h.Logger.Error().Err(err).Xid("trace_id", req.TraceID).Stringer("local_addr", req.LocalAddr).Str("remote_url", h.Config.ProxyPass).Msg("dns read raw data error")
		return
	}
	req.Message.Raw = req.Message.Raw[:n]

	req.Conn.WriteToUDPAddrPort(req.Message.Raw, req.RemoteAddr)
}
