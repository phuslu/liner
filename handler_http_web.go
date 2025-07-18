package main

import (
	"expvar"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"strings"
	"text/template"

	"github.com/phuslu/log"
)

type HTTPWebHandler struct {
	Config    HTTPConfig
	Transport *http.Transport
	Functions template.FuncMap

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
		switch {
		case web.Cgi.Enabled:
			routers = append(routers, router{
				web.Location,
				&HTTPWebCgiHandler{
					Location:   web.Location,
					Root:       web.Cgi.Root,
					DefaultApp: web.Cgi.DefaultAPP,
				},
			})
		case web.Dav.Enabled:
			routers = append(routers, router{
				web.Location,
				&HTTPWebDavHandler{
					Root:      web.Dav.Root,
					AuthTable: web.Dav.AuthTable,
				},
			})
		case web.Doh.Enabled:
			routers = append(routers, router{
				web.Location,
				&HTTPWebDohHandler{
					Policy:    web.Doh.Policy,
					ProxyPass: web.Doh.ProxyPass,
					Functions: h.Functions,
				},
			})
		case web.Index.Root != "" || web.Index.Body != "" || web.Index.File != "":
			routers = append(routers, router{
				web.Location,
				&HTTPWebIndexHandler{
					Functions: h.Functions,
					Location:  web.Location,
					Root:      web.Index.Root,
					Headers:   web.Index.Headers,
					Body:      web.Index.Body,
					File:      web.Index.File,
				},
			})
		case web.Proxy.Pass != "":
			routers = append(routers, router{
				web.Location,
				&HTTPWebProxyHandler{
					Transport:   h.Transport,
					Functions:   h.Functions,
					Pass:        web.Proxy.Pass,
					AuthTable:   web.Proxy.AuthTable,
					SetHeaders:  web.Proxy.SetHeaders,
					DumpFailure: web.Proxy.DumpFailure,
				},
			})
		}
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
		if ap, err := netip.ParseAddrPort(req.RemoteAddr); err == nil && !ap.Addr().IsLoopback() && !ap.Addr().IsPrivate() {
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
	if config, _ := h.Config.ServerConfig[req.Host]; !config.DisableHttp3 && req.ProtoMajor != 3 {
		_, port, _ := net.SplitHostPort(req.Context().Value(http.LocalAddrContextKey).(net.Addr).String())
		rw.Header().Add("Alt-Svc", `h3=":`+port+`"; ma=2592000,h3-29=":`+port+`"; ma=2592000`)
	}
	for _, x := range h.wildcards {
		if WildcardMatch(x.location, req.URL.Path) {
			x.handler.ServeHTTP(rw, req)
			return
		}
	}
	h.mux.ServeHTTP(rw, req)
}
