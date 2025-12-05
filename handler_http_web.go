package main

import (
	"crypto/tls"
	"expvar"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
)

type HTTPWebHandler struct {
	Config        HTTPConfig
	MemoryDialers *sync.Map
	Transport     *http.Transport
	Functions     template.FuncMap

	wildcards []struct {
		location string
		handler  HTTPHandler
	}
	mux *http.ServeMux
}

func (h *HTTPWebHandler) Load() error {
	type router struct {
		location string
		handler  HTTPHandler
	}

	var routers []router
	for _, web := range h.Config.Web {
		router := router{
			location: web.Location,
		}
		switch {
		case web.Dav.Enabled:
			router.handler = &HTTPWebDavHandler{
				Root:      web.Dav.Root,
				AuthTable: web.Dav.AuthTable,
			}
		case web.Doh.Enabled:
			router.handler = &HTTPWebDohHandler{
				Policy:    web.Doh.Policy,
				ProxyPass: web.Doh.ProxyPass,
				CacheSize: web.Doh.CacheSize,
				Functions: h.Functions,
			}
		case web.Fastcgi.Enabled:
			router.handler = &HTTPWebFastcgiHandler{
				Location: web.Location,
				Root:     web.Fastcgi.Root,
			}
		case web.Index.Root != "" || web.Index.Body != "" || web.Index.File != "":
			router.handler = &HTTPWebIndexHandler{
				Functions: h.Functions,
				Location:  web.Location,
				Root:      web.Index.Root,
				Headers:   web.Index.Headers,
				Charset:   web.Index.Charset,
				Body:      web.Index.Body,
				File:      web.Index.File,
			}
		case web.Proxy.Pass != "":
			router.handler = &HTTPWebProxyHandler{
				MemoryDialers: h.MemoryDialers,
				Transport:     h.Transport,
				Functions:     h.Functions,
				Pass:          web.Proxy.Pass,
				AuthTable:     web.Proxy.AuthTable,
				StripPrefix:   web.Proxy.StripPrefix,
				SetHeaders:    web.Proxy.SetHeaders,
				DumpFailure:   web.Proxy.DumpFailure,
			}
		case web.Shell.Enabled:
			router.handler = &HTTPWebShellHandler{
				Location:  web.Location,
				AuthTable: web.Shell.AuthTable,
				Command:   web.Shell.Command,
			}
		default:
			return fmt.Errorf("unsupported web handler config: %+v", web)
		}
		if tcpcongestion := strings.TrimSpace(web.TcpCongestion); tcpcongestion != "" {
			router.handler = &HTTPWebMiddlewareTcpCongestion{
				TcpCongestion: tcpcongestion,
				Functions:     h.Functions,
				Handler:       router.handler,
			}
		}
		routers = append(routers, router)
	}

	var root HTTPHandler
	h.mux = http.NewServeMux()
	for _, x := range routers {
		err := x.handler.Load()
		if err != nil {
			log.Fatal().Err(err).Str("web_location", x.location).Msgf("%T.Load() return error: %+v", x.handler, err)
		}
		log.Info().Str("web_location", x.location).Msgf("%T.Load() ok", x.handler)

		if x.location == "/" {
			root = x.handler
			continue
		}

		if strings.ContainsAny(x.location, "*?[]") {
			h.wildcards = append(h.wildcards, x)
			continue
		}

		h.mux.Handle(x.location, x.handler)
	}

	h.mux.HandleFunc("/debug/", func(rw http.ResponseWriter, req *http.Request) {
		ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
		if !ri.RemoteAddr.Addr().IsLoopback() && !ri.RemoteAddr.Addr().IsPrivate() {
			http.Error(rw, "403 forbidden", http.StatusForbidden)
			return
		}

		switch req.URL.Path {
		case "/debug/vars":
			expvar.Handler().ServeHTTP(rw, req)
		case "/debug/pprof/cmdline":
			pprof.Cmdline(rw, req)
		case "/debug/pprof/profile":
			pprof.Profile(rw, req)
		case "/debug/pprof/symbol":
			pprof.Symbol(rw, req)
		case "/debug/pprof/trace":
			pprof.Trace(rw, req)
		default:
			pprof.Index(rw, req)
		}
	})

	h.mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {

		if root != nil {
			root.ServeHTTP(rw, req)
			return
		}

		http.NotFound(rw, req)
	})

	return nil
}

func (h *HTTPWebHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if config, _ := h.Config.ServerConfig[req.Host]; !config.DisableHttp3 && req.ProtoMajor != 3 && req.TLS != nil {
		if addr, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr).(*net.TCPAddr); ok {
			rw.Header().Add("alt-svc", `h3=":`+strconv.Itoa(addr.Port)+`"`)
		}
	}
	for _, x := range h.wildcards {
		if WildcardMatch(x.location, req.URL.Path) {
			x.handler.ServeHTTP(rw, req)
			return
		}
	}
	h.mux.ServeHTTP(rw, req)
}

var _ HTTPHandler = (*HTTPWebMiddlewareTcpCongestion)(nil)

type HTTPWebMiddlewareTcpCongestion struct {
	TcpCongestion string
	Functions     template.FuncMap
	Handler       HTTPHandler

	template *template.Template
}

func (m *HTTPWebMiddlewareTcpCongestion) Load() error {
	if strings.Contains(m.TcpCongestion, "{{") {
		tmpl, err := template.New(m.TcpCongestion).Funcs(m.Functions).Parse(m.TcpCongestion)
		if err != nil {
			return err
		}
		m.template = tmpl
	}
	return m.Handler.Load()
}

func (m *HTTPWebMiddlewareTcpCongestion) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)

	if ri.ClientConnOps.SupportTCP() && m.TcpCongestion != "" {
		var tcpCongestion string
		if m.template != nil {
			ri.PolicyBuffer.Reset()
			err := m.template.Execute(&ri.PolicyBuffer, struct {
				Request         *http.Request
				RealIP          netip.Addr
				ClientHelloInfo *tls.ClientHelloInfo
				JA4             string
				UserAgent       *useragent.UserAgent
				ServerAddr      netip.AddrPort
				User            AuthUserInfo
			}{req, ri.RealIP, ri.ClientHelloInfo, ri.JA4, &ri.UserAgent, ri.ServerAddr, ri.ProxyUserInfo})
			if err != nil {
				log.Error().Err(err).Context(ri.LogContext).Str("forward_tcp_congestion", m.TcpCongestion).Msg("execute forward_tcp_congestion error")
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			tcpCongestion = strings.TrimSpace(b2s(ri.PolicyBuffer.B))
		} else {
			tcpCongestion = m.TcpCongestion
		}
		if tcpCongestion != "" {
			log.Debug().Context(ri.LogContext).Str("forward_tcp_congestion", tcpCongestion).Msg("execute forward_tcp_congestion ok")
			if options := strings.Fields(tcpCongestion); len(options) >= 1 {
				switch name := options[0]; name {
				case "brutal":
					if len(options) < 2 {
						log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("parse forward_tcp_congestion error")
						http.Error(rw, "invalid tcp_congestion value", http.StatusBadGateway)
						return
					}
					if rate, _ := strconv.Atoi(options[1]); rate > 0 {
						gain := 20 // hysteria2 default
						if len(options) >= 3 {
							if n, _ := strconv.Atoi(options[2]); n > 0 {
								gain = n
							}
						}
						if err := ri.ClientConnOps.SetTcpCongestion(name, uint64(rate), uint32(gain)); err != nil {
							log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion error")
							http.Error(rw, err.Error(), http.StatusBadGateway)
							return
						}
						log.Debug().NetIPAddr("remote_ip", ri.RealIP).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion ok")
					}
				default:
					if err := ri.ClientConnOps.SetTcpCongestion(name); err != nil {
						log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion error")
						http.Error(rw, err.Error(), http.StatusBadGateway)
						return
					}
				}
			}
		}
	}
	m.Handler.ServeHTTP(rw, req)
}
