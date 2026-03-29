package main

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"expvar"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"
	"text/template"

	"github.com/phuslu/log"
	"github.com/smallnest/ringbuffer"
)

type HTTPWebHandler struct {
	Config          HTTPConfig
	DnsResolverPool *DnsResolverPool
	MemoryDialers   *MemoryDialers
	MemoryLogWriter *ringbuffer.RingBuffer
	Transport       *http.Transport
	Functions       template.FuncMap

	wildcards []struct {
		location string
		handler  HTTPHandler
	}
	mux *http.ServeMux
}

func (h *HTTPWebHandler) Load(ctx context.Context) error {
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
				Root: web.Dav.Root,
			}
			router.handler = &HTTPWebMiddlewareAuthTable{
				ProxyUser: false,
				AuthTable: web.Dav.AuthTable,
				AllowAttr: "allow_webdav",
				Handler:   router.handler,
			}
		case web.Doh.Enabled:
			router.handler = &HTTPWebDohHandler{
				Policy:          web.Doh.Policy,
				ProxyPass:       web.Doh.ProxyPass,
				CacheSize:       web.Doh.CacheSize,
				Functions:       h.Functions,
				DnsResolverPool: h.DnsResolverPool,
			}
		case web.Index.Root != "" || web.Index.Body != "" || web.Index.File != "":
			router.handler = &HTTPWebIndexHandler{
				Location:  web.Location,
				Root:      web.Index.Root,
				Headers:   web.Index.Headers,
				Charset:   web.Index.Charset,
				Body:      web.Index.Body,
				File:      web.Index.File,
				Functions: h.Functions,
			}
			router.handler = &HTTPWebMiddlewareCDNJS{
				Location: web.Location,
				Handler:  router.handler,
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
				Command:   web.Shell.Command,
				Home:      web.Shell.Home,
				Template:  web.Shell.Template,
			}
			router.handler = &HTTPWebMiddlewareAuthTable{
				ProxyUser: false,
				AuthTable: web.Shell.AuthTable,
				AllowAttr: "allow_webshell",
				Handler:   router.handler,
			}
			router.handler = &HTTPWebMiddlewareCDNJS{
				Location: web.Location,
				Handler:  router.handler,
			}
		case web.Logtail.Enabled:
			router.handler = &HTTPWebLogtailHandler{
				Location:        web.Location,
				MemoryLogWriter: h.MemoryLogWriter,
			}
			router.handler = &HTTPWebMiddlewareAuthTable{
				ProxyUser: false,
				AuthTable: web.Logtail.AuthTable,
				AllowAttr: "allow_logtail",
				Handler:   router.handler,
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
		err := x.handler.Load(ctx)
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

var _ HTTPHandler = (*HTTPWebMiddlewareCDNJS)(nil)

var HTTPCDNJSReplacerContextKey any = &HTTPContextKey{"http-cdnjs-replacer"}

type HTTPWebMiddlewareCDNJS struct {
	Location string
	Handler  HTTPHandler

	prefix   string
	handler  http.Handler
	replacer *strings.Replacer
}

//go:embed cdnjs.zip
var cdnjsZip []byte

func (m *HTTPWebMiddlewareCDNJS) Load(ctx context.Context) error {
	zipreader, err := zip.NewReader(bytes.NewReader(cdnjsZip), int64(len(cdnjsZip)))
	if err != nil {
		return err
	}

	m.prefix = strings.TrimSuffix(m.Location, "/") + "/.cdnjs/"
	m.handler = http.StripPrefix(strings.TrimSuffix(m.prefix, "/"), http.FileServer(http.FS(zipreader)))
	m.replacer = strings.NewReplacer(
		"https://cdnjs.cloudflare.com/", m.prefix+"cdnjs.cloudflare.com/",
		"https://cdn.jsdelivr.net/", m.prefix+"cdn.jsdelivr.net/",
	)

	return m.Handler.Load(context.WithValue(ctx, HTTPCDNJSReplacerContextKey, m.replacer))
}

func (m *HTTPWebMiddlewareCDNJS) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	if strings.HasPrefix(req.RequestURI, m.prefix) {
		m.handler.ServeHTTP(rw, req)
		return
	}
	m.Handler.ServeHTTP(rw, req)
}

var _ HTTPHandler = (*HTTPWebMiddlewareAuthTable)(nil)

type HTTPWebMiddlewareAuthTable struct {
	ProxyUser bool
	AuthTable string
	AllowAttr string
	Handler   HTTPHandler

	userchecker AuthUserChecker
}

func (m *HTTPWebMiddlewareAuthTable) Load(ctx context.Context) error {
	if m.AuthTable != "" {
		loader := NewAuthUserLoaderFromTable(m.AuthTable)
		_, err := loader.LoadAuthUsers(ctx)
		if err != nil {
			return err
		}
		m.userchecker = &AuthUserLoadChecker{loader}
	}

	return m.Handler.Load(ctx)
}

func (m *HTTPWebMiddlewareAuthTable) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if m.userchecker != nil {
		ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
		var err error
		if m.ProxyUser {
			err = m.userchecker.CheckAuthUser(req.Context(), &ri.ProxyUserInfo)
		} else {
			err = m.userchecker.CheckAuthUser(req.Context(), &ri.AuthUserInfo)
		}
		if err == nil && m.AllowAttr != "" {
			if allow := ri.AuthUserInfo.Attrs[m.AllowAttr]; allow != "1" {
				err = fmt.Errorf("%q is not true of user: %#v", m.AllowAttr, ri.AuthUserInfo.Username)
			}
		}
		if err != nil {
			rw.Header().Set("www-authenticate", `Basic realm="Login to continue"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)
			return
		}
	}
	m.Handler.ServeHTTP(rw, req)
}

var _ HTTPHandler = (*HTTPWebMiddlewareForwardAuth)(nil)

type HTTPWebMiddlewareForwardAuth struct {
	ForwardAuth string
	Functions   template.FuncMap
	Handler     HTTPHandler
}

func (m *HTTPWebMiddlewareForwardAuth) Load(ctx context.Context) error {
	return m.Handler.Load(ctx)
}

func (m *HTTPWebMiddlewareForwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	m.Handler.ServeHTTP(rw, req)
}
