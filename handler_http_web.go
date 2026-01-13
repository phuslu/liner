package main

import (
	"expvar"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/phuslu/log"
	"github.com/smallnest/ringbuffer"
)

type HTTPWebHandler struct {
	Config          HTTPConfig
	DnsResolverPool *DnsResolverPool
	MemoryDialers   *sync.Map
	MemoryLogWriter *ringbuffer.RingBuffer
	Transport       *http.Transport
	Functions       template.FuncMap

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
				Policy:          web.Doh.Policy,
				ProxyPass:       web.Doh.ProxyPass,
				CacheSize:       web.Doh.CacheSize,
				Functions:       h.Functions,
				DnsResolverPool: h.DnsResolverPool,
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
				Functions: h.Functions,
				AuthTable: web.Shell.AuthTable,
				Command:   web.Shell.Command,
				Home:      web.Shell.Home,
				Template:  web.Shell.Template,
			}
		case web.Logtail.Enabled:
			router.handler = &HTTPWebLogtailHandler{
				Location:        web.Location,
				AuthTable:       web.Logtail.AuthTable,
				MemoryLogWriter: h.MemoryLogWriter,
			}
		default:
			log.Info().Str("web_location", web.Location).Msgf("web location is not enabled, skip.")
			continue
		}
		if forwardAuth := strings.TrimSpace(web.ForwardAuth); forwardAuth != "" {
			router.handler = &HTTPWebMiddlewareForwardAuth{
				ForwardAuth: forwardAuth,
				Functions:   h.Functions,
				Handler:     router.handler,
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
	if config := h.Config.ServerConfig[req.Host]; !config.DisableHttp3 && req.ProtoMajor != 3 && req.TLS != nil {
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

var _ HTTPHandler = (*HTTPWebMiddlewareForwardAuth)(nil)

type HTTPWebMiddlewareForwardAuth struct {
	ForwardAuth string
	Functions   template.FuncMap
	Handler     HTTPHandler
}

func (m *HTTPWebMiddlewareForwardAuth) Load() error {
	return m.Handler.Load()
}

func (m *HTTPWebMiddlewareForwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	m.Handler.ServeHTTP(rw, req)
}
