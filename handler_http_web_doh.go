package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"text/template"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
)

type HTTPWebDohHandler struct {
	Policy    string
	ProxyPass string
	Functions template.FuncMap

	dialer fastdns.Dialer
	policy *template.Template
}

func (h *HTTPWebDohHandler) Load() error {
	resolver, err := GetResolver(h.ProxyPass)
	if err != nil {
		return fmt.Errorf("invaild doh proxy_pass: %#v: %w", h.ProxyPass, err)
	}

	h.dialer = resolver.Client.Dialer

	if s := h.Policy; s != "" && s != "proxy_pass" {
		h.policy, err = template.New(s).Funcs(h.Functions).Parse(s)
		if err != nil {
			return fmt.Errorf("invaild doh policy: %#v: %w", s, err)
		}
	}

	return nil
}

func (h *HTTPWebDohHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	if req.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(rw, "Unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	dr := drPool.Get().(*DnsRequest)
	defer func() {
		if len(dr.Message.Raw) <= 4096 {
			drPool.Put(dr)
		}
	}()

	var err error

	dr.Message.Raw, _, err = AppendReadFrom(dr.Message.Raw[:0], req.Body)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Error().Context(ri.LogContext).Err(err).Msg("doh read from request body error")
		http.Error(rw, "DNS query not specified or too small: "+err.Error(), http.StatusBadRequest)
		return
	}

	dr.LocalAddr = ri.ServerAddr
	dr.RemoteAddr = ri.RemoteAddr
	dr.Proto = "doh"
	dr.Domain = ""
	dr.QType = ""

	proxypass, dialer := h.ProxyPass, h.dialer
	if h.policy != nil {
		err := fastdns.ParseMessage(dr.Message, dr.Message.Raw, false)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Msg("dns parse message error")
			return
		}

		dr.Domain = b2s(AppendToLower(make([]byte, 0, 256), b2s(dr.Message.Domain)))
		dr.QType = dr.Message.Question.Type.String()

		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)

		bb.Reset()
		err = h.policy.Execute(bb, struct {
			Request *http.Request
			Dns     *DnsRequest
		}{req, dr})
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Context(ri.LogContext).Msg("dns execute policy error")
			return
		}

		policyName := strings.TrimSpace(bb.String())

		if code, _ := strconv.Atoi(policyName); 100 <= code && code <= 999 {
			// msg := fmt.Sprintf("%d %s", code, http.StatusText(code))
			msg := string(AppendableBytes(make([]byte, 0, 128)).Int64(int64(code), 10).Byte(' ').Str(http.StatusText(code)))
			http.Error(rw, msg, code)
			return
		}

		log.Debug().Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).Str("forward_policy_name", policyName).Msg("execute forward_policy ok")

		toaddrs := func(dst []netip.Addr, ss []string) []netip.Addr {
			for _, s := range ss {
				if addr, err := netip.ParseAddr(s); err == nil {
					dst = append(dst, addr)
				}
			}
			return dst
		}

		drw := dohResponseWriter{rw, dr}
		parts := strings.Fields(policyName)
		switch parts[0] {
		case "ERROR", "error":
			if len(parts) != 2 {
				fastdns.Error(drw, dr.Message, fastdns.RcodeServFail)
				return
			}
			rcode, err := fastdns.ParseRcode(parts[1])
			if err != nil {
				log.Error().Context(ri.LogContext).Err(err).Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).Msg("dns policy parse rcode error")
				fastdns.Error(drw, dr.Message, fastdns.RcodeServFail)
				return
			}
			log.Debug().Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).Stringer("rcode", rcode).Msg("dns policy error executed")
			fastdns.Error(drw, dr.Message, rcode)
			return
		case "HOST", "host":
			addrs := toaddrs(make([]netip.Addr, 0, 4), parts[1:])
			log.Debug().Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).NetIPAddrs("hosts", addrs).Msg("dns policy host executed")
			fastdns.HOST(drw, dr.Message, 300, addrs)
			return
		case "CNAME", "cname":
			if len(parts) != 2 {
				fastdns.Error(drw, dr.Message, fastdns.RcodeServFail)
				return
			}
			cnames := strings.Split(parts[1], ",")
			log.Debug().Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).Strs("cnames", cnames).Msg("dns policy cname executed")
			fastdns.CNAME(drw, dr.Message, 300, cnames, nil)
			return
		case "TXT", "txt":
			if len(parts) != 2 {
				fastdns.Error(drw, dr.Message, fastdns.RcodeServFail)
				return
			}
			txt := parts[1]
			log.Debug().Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).Str("txt", txt).Msg("dns policy txt executed")
			fastdns.TXT(drw, dr.Message, 300, txt)
			return
		case "PROXY_PASS", "proxy_pass":
			if len(parts) == 2 {
				proxypass = parts[1]
				resolver, err := GetResolver(proxypass)
				if err != nil {
					log.Error().Context(ri.LogContext).Err(err).Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).Str("proxy_pass", proxypass).Msg("dns policy parse proxy_pass error")
					fastdns.Error(drw, dr.Message, fastdns.RcodeServFail)
					return
				}
				dialer = resolver.Client.Dialer
				log.Debug().Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).Str("proxy_pass", proxypass).Msg("dns policy proxy_pass executed")
			}
		}
		defer log.Info().Context(ri.LogContext).Str("doh_req_domain", dr.Domain).Str("doh_req_qtype", dr.QType).Str("proxy_pass", proxypass).Msg("dns proxy_pass request")
	} else {
		defer func() {
			err := fastdns.ParseMessage(dr.Message, dr.Message.Raw, false)
			if err != nil {
				log.Error().Context(ri.LogContext).Err(err).Msg("dns parse message error")
				return
			}
			log.Info().Context(ri.LogContext).Bytes("doh_req_domain", dr.Message.Domain).Str("doh_req_qtype", dr.Message.Question.Type.String()).Str("proxy_pass", proxypass).Msg("dns proxy_pass request")
		}()
	}

	conn, err := dialer.DialContext(req.Context(), "", "")
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Context(ri.LogContext).Str("proxy_pass", proxypass).Msg("doh dial error")
		http.Error(rw, "DNS internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if d, _ := dialer.(interface {
		Put(c net.Conn)
	}); d != nil {
		defer d.Put(conn)
	}

	_, err = conn.Write(dr.Message.Raw)
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Context(ri.LogContext).Str("proxy_pass", proxypass).Msg("doh dial error")
		http.Error(rw, "DNS internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	dr.Message.Raw, _, err = AppendReadFrom(dr.Message.Raw[:0], conn)
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Context(ri.LogContext).Str("proxy_pass", proxypass).Msg("doh read raw data error")
		http.Error(rw, "DNS internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/dns-message")
	rw.WriteHeader(http.StatusOK)
	rw.Write(dr.Message.Raw)
}

type dohResponseWriter struct {
	rw http.ResponseWriter
	dr *DnsRequest
}

func (w dohResponseWriter) LocalAddr() netip.AddrPort {
	return w.dr.LocalAddr
}

func (w dohResponseWriter) RemoteAddr() netip.AddrPort {
	return w.dr.RemoteAddr
}

func (w dohResponseWriter) Write(b []byte) (int, error) {
	w.rw.Header().Set("Content-Type", "application/dns-message")
	w.rw.WriteHeader(http.StatusOK)
	return w.rw.Write(w.dr.Message.Raw)
}

var _ fastdns.ResponseWriter = dohResponseWriter{}
