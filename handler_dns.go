package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
)

type DnsHandler struct {
	Config    DnsConfig
	Functions template.FuncMap
	Logger    log.Logger

	dialer fastdns.Dialer
	policy *template.Template
}

type DnsRequest struct {
	LogContext log.Context
	LocalAddr  netip.AddrPort
	RemoteAddr netip.AddrPort
	Message    *fastdns.Message
	Proto      string
	Domain     string
	QType      string
}

var drPool = sync.Pool{
	New: func() interface{} {
		r := new(DnsRequest)
		r.Message = fastdns.AcquireMessage()
		return r
	},
}

func (h *DnsHandler) Load() error {
	resolver, err := GetResolver(h.Config.ProxyPass)
	if err != nil {
		return fmt.Errorf("invaild dns proxy_pass: %#v: %w", h.Config.ProxyPass, err)
	}

	h.dialer = resolver.Client.Dialer

	if s := h.Config.Policy; s != "" && s != "proxy_pass" {
		h.policy, err = template.New(s).Funcs(h.Functions).Parse(s)
		if err != nil {
			return fmt.Errorf("invaild dns policy: %#v: %w", s, err)
		}
	}

	return nil
}

func (h *DnsHandler) Serve(ctx context.Context, conn *net.UDPConn) {
	defer conn.Close()

	laddr, _ := netip.ParseAddrPort(conn.LocalAddr().String())

	for {
		req := drPool.Get().(*DnsRequest)

		req.Message.Raw = req.Message.Raw[:cap(req.Message.Raw)]
		n, addr, err := conn.ReadFromUDPAddrPort(req.Message.Raw)
		if err != nil {
			log.Error().Err(err).NetIPAddrPort("local_addr", laddr).Msg("dns read from udp error")
			continue
		}
		req.Message.Raw = req.Message.Raw[:n]

		req.LocalAddr = laddr
		req.RemoteAddr = addr
		req.Proto = "dns"
		req.Domain = ""
		req.QType = ""

		rw := dnsResponseWriter{conn, req.LocalAddr, req.RemoteAddr}

		go h.ServeDNS(ctx, rw, req)
	}
}

func (h *DnsHandler) ServeTCP(ctx context.Context, ln net.Listener) {
	defer ln.Close()

	laddr, _ := netip.ParseAddrPort(ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		go func(ctx context.Context, conn net.Conn) {
			raddr, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
			br := bufio.NewReader(conn)
			for {
				var n uint16
				err := binary.Read(br, binary.BigEndian, &n)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						log.Error().Err(err).NetIPAddrPort("remote_addr", raddr).Msg("dot read dns message header error")
					}
					conn.Close()
					return
				}

				req := drPool.Get().(*DnsRequest)
				req.Message.Raw, _, err = AppendReadFrom(req.Message.Raw[:0], io.LimitReader(br, int64(n)))
				if err != nil {
					log.Error().Err(err).NetIPAddrPort("remote_addr", raddr).Msg("dot read dns message data error")
					conn.Close()
					return
				}

				req.LocalAddr = laddr
				req.RemoteAddr = raddr
				req.Proto = "dot"
				req.Domain = ""
				req.QType = ""

				rw := dotResponseWriter{conn, req.LocalAddr, req.RemoteAddr}

				h.ServeDNS(ctx, rw, req)
			}
		}(ctx, conn)
	}
}

func (h *DnsHandler) ServeDNS(ctx context.Context, rw fastdns.ResponseWriter, req *DnsRequest) {
	defer func() {
		if len(req.Message.Raw) <= 4096 {
			drPool.Put(req)
		}
	}()

	req.LogContext = log.NewContext(req.LogContext[:0]).Xid("trace_id", log.NewXID()).Str("dns_proto", req.Proto).NetIPAddrPort("local_addr", req.LocalAddr).NetIPAddr("remote_addr", req.RemoteAddr.Addr()).Value()

	proxypass, dialer := h.Config.ProxyPass, h.dialer
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
		case "PROXY_PASS", "proxy_pass":
			if len(parts) == 2 {
				proxypass = parts[1]
				resolver, err := GetResolver(proxypass)
				if err != nil {
					h.Logger.Error().Err(err).Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).Str("proxy_pass", proxypass).Msg("dns policy parse proxy_pass error")
					fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
					return
				}
				dialer = resolver.Client.Dialer
				h.Logger.Debug().Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).Str("proxy_pass", proxypass).Msg("dns policy proxy_pass executed")
			}
		}
		defer h.Logger.Info().Context(req.LogContext).Str("req_domain", req.Domain).Str("req_qtype", req.QType).Str("proxy_pass", proxypass).Msg("dns proxy_pass request")
	} else {
		defer func() {
			err := fastdns.ParseMessage(req.Message, req.Message.Raw, false)
			if err != nil {
				h.Logger.Error().Err(err).Msg("dns parse message error")
				return
			}
			h.Logger.Info().Context(req.LogContext).Bytes("req_domain", req.Message.Domain).Str("req_qtype", req.Message.Question.Type.String()).Str("proxy_pass", proxypass).Msg("dns proxy_pass request")
		}()
	}

	conn, err := dialer.DialContext(ctx, "", "")
	if err != nil {
		h.Logger.Error().Err(err).Context(req.LogContext).Str("proxy_pass", proxypass).Msg("dns dial error")
		return
	}
	if d, _ := dialer.(interface {
		Put(c net.Conn)
	}); d != nil {
		defer d.Put(conn)
	}

	_, err = conn.Write(req.Message.Raw)
	if err != nil {
		h.Logger.Error().Err(err).Context(req.LogContext).Str("proxy_pass", proxypass).Msg("dns dial error")
		return
	}

	req.Message.Raw = req.Message.Raw[:cap(req.Message.Raw)]
	n, err := conn.Read(req.Message.Raw)
	if err != nil {
		h.Logger.Error().Err(err).Context(req.LogContext).Str("proxy_pass", proxypass).Msg("dns read raw data error")
		return
	}
	req.Message.Raw = req.Message.Raw[:n]

	rw.Write(req.Message.Raw)
}

type dnsResponseWriter struct {
	conn  *net.UDPConn
	laddr netip.AddrPort
	raddr netip.AddrPort
}

func (w dnsResponseWriter) LocalAddr() netip.AddrPort {
	return w.laddr
}

func (w dnsResponseWriter) RemoteAddr() netip.AddrPort {
	return w.raddr
}

func (w dnsResponseWriter) Write(b []byte) (int, error) {
	return w.conn.WriteToUDPAddrPort(b, w.raddr)
}

var _ fastdns.ResponseWriter = dnsResponseWriter{}

type dotResponseWriter struct {
	conn  net.Conn
	laddr netip.AddrPort
	raddr netip.AddrPort
}

func (w dotResponseWriter) LocalAddr() netip.AddrPort {
	return w.laddr
}

func (w dotResponseWriter) RemoteAddr() netip.AddrPort {
	return w.raddr
}

func (w dotResponseWriter) Write(data []byte) (int, error) {
	n := uint16(len(data))
	b := make([]byte, 0, 2048)
	b = append(b, byte(n>>8), byte(n&0xff))
	b = append(b, data...)
	return w.conn.Write(b)
}

var _ fastdns.ResponseWriter = dotResponseWriter{}
