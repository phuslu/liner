package main

import (
	"archive/zip"
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"path"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/phuslu/log"
	"github.com/phuslu/lru"
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
			if table := web.Dav.AuthTable; table != "" {
				router.handler = &HTTPWebMiddlewareAuthTable{
					Handler:   router.handler,
					Location:  router.location,
					AuthTable: table,
					AllowAttr: "allow_webdav",
				}
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
			if table := web.Index.AuthTable; table != "" {
				router.handler = &HTTPWebMiddlewareAuthTable{
					Handler:   router.handler,
					Location:  router.location,
					AuthTable: table,
					AllowAttr: "allow_index",
				}
			}
			router.handler = &HTTPWebMiddlewareCDNJS{
				Handler:  router.handler,
				Location: router.location,
			}
		case web.Proxy.Pass != "":
			router.handler = &HTTPWebProxyHandler{
				MemoryDialers: h.MemoryDialers,
				Transport:     h.Transport,
				Functions:     h.Functions,
				Pass:          web.Proxy.Pass,
				StripPrefix:   web.Proxy.StripPrefix,
				SetHeaders:    web.Proxy.SetHeaders,
				DumpFailure:   web.Proxy.DumpFailure,
			}
			if table := web.Proxy.AuthTable; table != "" {
				router.handler = &HTTPWebMiddlewareAuthTable{
					Handler:   router.handler,
					Location:  router.location,
					AuthTable: table,
					AllowAttr: "allow_proxy",
				}
			}
			if tiny := web.Proxy.TinyAuth; tiny != "" {
				router.handler = &HTTPWebMiddlewareTinyAuth{
					Handler:   router.handler,
					Location:  router.location,
					TinyAuth:  tiny,
					Transport: h.Transport,
				}
			}
		case web.Shell.Enabled:
			router.handler = &HTTPWebShellHandler{
				Location:  web.Location,
				Functions: h.Functions,
				Command:   web.Shell.Command,
				Home:      web.Shell.Home,
				Template:  web.Shell.Template,
			}
			if table := web.Shell.AuthTable; table != "" {
				router.handler = &HTTPWebMiddlewareAuthTable{
					Handler:   router.handler,
					Location:  router.location,
					AuthTable: table,
					AllowAttr: "allow_webshell",
				}
			}
			if tiny := web.Shell.TinyAuth; tiny != "" {
				router.handler = &HTTPWebMiddlewareTinyAuth{
					Handler:   router.handler,
					Location:  router.location,
					TinyAuth:  tiny,
					Transport: h.Transport,
				}
			}
			router.handler = &HTTPWebMiddlewareCDNJS{
				Handler:  router.handler,
				Location: router.location,
			}
		case web.Logtail.Enabled:
			router.handler = &HTTPWebLogtailHandler{
				Location:        web.Location,
				MemoryLogWriter: h.MemoryLogWriter,
			}
			if table := web.Logtail.AuthTable; table != "" {
				router.handler = &HTTPWebMiddlewareAuthTable{
					Handler:   router.handler,
					Location:  router.location,
					AuthTable: table,
					AllowAttr: "allow_logtail",
				}
			}
		default:
			log.Info().Str("web_location", web.Location).Msgf("web location is not enabled, skip.")
			continue
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
	Handler  HTTPHandler
	Location string

	prefix     string
	filesystem http.FileSystem
	replacer   *strings.Replacer
}

//go:embed cdnjs.zip
var cdnjsZip []byte

func (m *HTTPWebMiddlewareCDNJS) Load(ctx context.Context) error {
	zipreader, err := zip.NewReader(bytes.NewReader(cdnjsZip), int64(len(cdnjsZip)))
	if err != nil {
		return err
	}

	m.prefix = strings.TrimSuffix(m.Location, "/") + "/.cdnjs/"
	m.filesystem = http.FS(zipreader)
	m.replacer = strings.NewReplacer(
		"https://cdnjs.cloudflare.com/", m.prefix+"cdnjs.cloudflare.com/",
		"https://cdn.jsdelivr.net/", m.prefix+"cdn.jsdelivr.net/",
	)

	return m.Handler.Load(context.WithValue(ctx, HTTPCDNJSReplacerContextKey, m.replacer))
}

func (m *HTTPWebMiddlewareCDNJS) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	if strings.HasPrefix(req.RequestURI, m.prefix) {
		name := req.RequestURI[len(m.prefix):]
		file, err := m.filesystem.Open(name)
		if err != nil {
			http.Redirect(rw, req, "https://"+name, http.StatusTemporaryRedirect)
			return
		}
		defer file.Close()
		rw.Header().Set("cache-control", "public, max-age=30672000")
		rw.Header().Set("access-control-allow-origin", "*")
		if fi, err := file.Stat(); err == nil {
			rw.Header().Set("last-modified", fi.ModTime().Format(time.RFC1123))
			rw.Header().Set("content-length", strconv.FormatInt(fi.Size(), 10))
		}
		rw.Header().Set("content-type", cmp.Or(GetMimeTypeByExtension(path.Ext(name)), "text/plain; charset=utf-8"))
		io.Copy(rw, file)
		return
	}
	m.Handler.ServeHTTP(rw, req)
}

var _ HTTPHandler = (*HTTPWebMiddlewareAuthTable)(nil)

type HTTPWebMiddlewareAuthTable struct {
	Handler  HTTPHandler
	Location string

	AuthTable string
	AllowAttr string

	prefix      string
	userchecker AuthUserChecker
}

func (m *HTTPWebMiddlewareAuthTable) Load(ctx context.Context) error {
	m.prefix = strings.TrimSuffix(m.Location, "/") + "/"
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
	if strings.HasPrefix(req.RequestURI, m.prefix) && m.userchecker != nil {
		ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
		err := m.userchecker.CheckAuthUser(req.Context(), &ri.AuthUserInfo)
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

var _ HTTPHandler = (*HTTPWebMiddlewareTinyAuth)(nil)

type HTTPWebMiddlewareTinyAuth struct {
	Handler  HTTPHandler
	Location string

	TinyAuth  string
	Transport *http.Transport

	prefix   string
	userinfo *lru.TTLCache[string, *TinyAuthUserInfo] // key: tinyauth-session-<id>=<uuid>
}

// TinyAuthUserInfo is tinyauth user info, see https://demo.tinyauth.app/api/context/user
type TinyAuthUserInfo struct {
	Status      int    `json:"status"`
	Message     string `json:"message"`
	IsLoggedIn  bool   `json:"isLoggedIn"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Provider    string `json:"provider"`
	Oauth       bool   `json:"oauth"`
	TotpPending bool   `json:"totpPending"`
	OauthName   string `json:"oauthName"`
}

func (m *HTTPWebMiddlewareTinyAuth) Load(ctx context.Context) error {
	m.prefix = strings.TrimSuffix(m.Location, "/") + "/"
	m.userinfo = lru.NewTTLCache[string, *TinyAuthUserInfo](1024)
	return m.Handler.Load(ctx)
}

func (m *HTTPWebMiddlewareTinyAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	if strings.HasPrefix(req.RequestURI, m.prefix) {
		var cookie string
		for _, c := range req.Cookies() {
			if strings.HasPrefix(c.Name, "tinyauth-session-") {
				cookie = c.Name + "=" + c.Value
				break
			}
		}
		if cookie == "" {
			http.Redirect(rw, req, fmt.Sprintf("https://%s/login?redirect_uri=https://%s%s", m.TinyAuth, req.Host, req.RequestURI), http.StatusTemporaryRedirect)
			return
		}
		info, err, _ := m.userinfo.GetOrLoad(req.Context(), cookie, func(ctx context.Context, cookie string) (*TinyAuthUserInfo, time.Duration, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/api/context/user", m.TinyAuth), nil)
			if err != nil {
				return nil, 0, err
			}
			req.Header.Add("Cookie", cookie)
			resp, err := m.Transport.RoundTrip(req)
			if err != nil {
				return nil, 0, fmt.Errorf("invaild tinyauth response: %w", err)
			}
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, 0, fmt.Errorf("invaild tinyauth response: %w", err)
			}
			if resp.StatusCode != http.StatusOK {
				return nil, 0, fmt.Errorf("invaild tinyauth response: %s", data)
			}
			info := new(TinyAuthUserInfo)
			err = json.Unmarshal(data, info)
			if err != nil {
				return nil, 0, fmt.Errorf("invaild tinyauth response: %s", data)
			}
			return info, 2 * time.Hour, nil
		})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		if info.Status != http.StatusOK {
			http.Redirect(rw, req, fmt.Sprintf("https://%s/login?redirect_uri=https://%s%s", m.TinyAuth, req.Host, req.RequestURI), http.StatusTemporaryRedirect)
			// http.Error(rw, "invaild username or password", http.StatusForbidden)
			return
		}
	}
	m.Handler.ServeHTTP(rw, req)
}
