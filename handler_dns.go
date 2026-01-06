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
)

type DnsHandler struct {
	Config          DnsConfig
	Functions       template.FuncMap
	DataLogger      log.Logger
	DnsResolverPool *DnsResolverPool

	dialer fastdns.Dialer
	policy *template.Template
}

type DnsRequest struct {
	LogContext   log.Context
	LocalAddr    netip.AddrPort
	RemoteAddr   netip.AddrPort
	Message      *fastdns.Message
	PolicyBuffer WritableBytes
	domain       []byte
	Proto        string
	QType        string
}

func (req *DnsRequest) Domain() string {
	return b2s(req.domain)
}

var drPool = sync.Pool{
	New: func() any {
		r := new(DnsRequest)
		r.Message = fastdns.AcquireMessage()
		r.PolicyBuffer.B = make([]byte, 0, 256)
		r.domain = make([]byte, 0, 256)
		return r
	},
}

func (h *DnsHandler) Load() error {
	resolver, err := h.DnsResolverPool.Get(h.Config.ProxyPass, 600*time.Second)
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

	laddr := AddrPortFromNetAddr(conn.LocalAddr())

	for {
		req := drPool.Get().(*DnsRequest)

		req.Message.Raw = req.Message.Raw[:cap(req.Message.Raw)]
		n, addrport, err := conn.ReadFromUDPAddrPort(req.Message.Raw)
		if err != nil {
			log.Error().Err(err).NetIPAddrPort("local_addr", laddr).Msg("dns read from udp error")
			continue
		}
		if addr := addrport.Addr(); addr.Is4In6() {
			addrport = netip.AddrPortFrom(addr.Unmap(), addrport.Port())
		}
		req.Message.Raw = req.Message.Raw[:n]
		req.PolicyBuffer.Reset()
		req.domain = req.domain[:0]
		req.Proto = "dns"
		req.QType = ""
		req.LocalAddr = laddr
		req.RemoteAddr = addrport
		rw := dnsResponseWriter{conn, req.LocalAddr, req.RemoteAddr}

		go h.ServeDNS(ctx, rw, req)
	}
}

func (h *DnsHandler) ServeTCP(ctx context.Context, ln net.Listener) {
	defer ln.Close()

	laddr := AddrPortFromNetAddr(ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		go func(ctx context.Context, conn net.Conn) {
			raddr := AddrPortFromNetAddr(conn.RemoteAddr())
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

				req.domain = req.domain[:0]
				req.Proto = "dot"
				req.QType = ""
				req.LocalAddr = laddr
				req.RemoteAddr = raddr

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
			log.Error().Err(err).Msg("dns parse message error")
			return
		}

		req.domain = AppendToLower(req.domain[:0], b2s(req.Message.Domain))
		req.QType = req.Message.Question.Type.String()

		req.PolicyBuffer.Reset()
		err = h.policy.Execute(&req.PolicyBuffer, struct {
			Request *DnsRequest
		}{req})
		if err != nil {
			log.Error().Err(err).Context(req.LogContext).Msg("dns execute policy error")
			return
		}

		policyName := strings.TrimSpace(b2s(req.PolicyBuffer.B))
		log.Debug().Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).Str("forward_policy_name", policyName).Msg("execute forward_policy ok")

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
				log.Error().Err(err).Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).Msg("dns policy parse rcode error")
				fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
				return
			}
			log.Debug().Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).Str("rcode", rcode.String()).Msg("dns policy error executed")
			fastdns.Error(rw, req.Message, rcode)
			return
		case "HOST", "host":
			addrs := toaddrs(make([]netip.Addr, 0, 4), parts[1:])
			log.Debug().Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).NetIPAddrs("hosts", addrs).Msg("dns policy host executed")
			req.Message.SetResponseHeader(fastdns.RcodeNoError, uint16(len(addrs)))
			req.Message.AppendHOST(300, addrs)
			rw.Write(req.Message.Raw)
			return
		case "CNAME", "cname":
			if len(parts) < 2 {
				fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
				return
			}
			var cnames []string
			addrs := parts[1:]
			for len(addrs) > 0 {
				if _, err := netip.ParseAddr(addrs[0]); err == nil {
					break
				}
				cnames = append(cnames, addrs[0])
				addrs = addrs[1:]
			}
			var ips []netip.Addr
			if len(addrs) > 0 {
				ips = toaddrs(make([]netip.Addr, 0, 4), addrs)
			}
			log.Debug().Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).Strs("cnames", cnames).NetIPAddrs("ips", ips).Msg("dns policy cname executed")
			req.Message.SetResponseHeader(fastdns.RcodeNoError, uint16(len(cnames)+len(ips)))
			req.Message.AppendCNAME(300, cnames, ips)
			rw.Write(req.Message.Raw)
			return
		case "TXT", "txt":
			if len(parts) != 2 {
				fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
				return
			}
			txt := parts[1]
			log.Debug().Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).Str("txt", txt).Msg("dns policy txt executed")
			req.Message.SetResponseHeader(fastdns.RcodeNoError, 1)
			req.Message.AppendTXT(300, txt)
			rw.Write(req.Message.Raw)
			return
		case "PROXY_PASS", "proxy_pass":
			if len(parts) == 2 {
				proxypass = parts[1]
				resolver, err := h.DnsResolverPool.Get(proxypass, 600*time.Second)
				if err != nil {
					log.Error().Err(err).Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).Str("proxy_pass", proxypass).Msg("dns policy parse proxy_pass error")
					fastdns.Error(rw, req.Message, fastdns.RcodeServFail)
					return
				}
				dialer = resolver.Client.Dialer
				log.Debug().Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).Str("proxy_pass", proxypass).Msg("dns policy proxy_pass executed")
			}
		}
		defer h.DataLogger.Log().Str("logger", "dns").Context(req.LogContext).Str("req_domain", req.Domain()).Str("req_qtype", req.QType).Str("proxy_pass", proxypass).Msg("")
	} else {
		defer func() {
			err := fastdns.ParseMessage(req.Message, req.Message.Raw, false)
			if err != nil {
				log.Error().Err(err).Msg("dns parse message error")
				return
			}
			h.DataLogger.Log().Str("logger", "dns").Context(req.LogContext).Bytes("req_domain", req.Message.Domain).Str("req_qtype", req.Message.Question.Type.String()).Str("proxy_pass", proxypass).Msg("")
		}()
	}

	conn, err := dialer.DialContext(ctx, "", "")
	if err != nil {
		log.Error().Err(err).Context(req.LogContext).Str("proxy_pass", proxypass).Msg("dns dial error")
		return
	}
	if d, _ := dialer.(interface {
		Put(c net.Conn)
	}); d != nil {
		defer d.Put(conn)
	}

	_, err = conn.Write(req.Message.Raw)
	if err != nil {
		log.Error().Err(err).Context(req.LogContext).Str("proxy_pass", proxypass).Msg("dns dial error")
		return
	}

	req.Message.Raw = req.Message.Raw[:cap(req.Message.Raw)]
	n, err := conn.Read(req.Message.Raw)
	if err != nil {
		log.Error().Err(err).Context(req.LogContext).Str("proxy_pass", proxypass).Msg("dns read raw data error")
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
