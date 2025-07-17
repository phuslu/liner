package main

import (
	"cmp"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
	"github.com/puzpuzpuz/xsync/v4"
	"golang.org/x/crypto/bcrypt"
)

type HTTPHandler interface {
	http.Handler
	Load() error
}

type HTTPServerHandler struct {
	Config         HTTPConfig
	ServerNames    []string
	ClientHelloMap *xsync.Map[string, *TLSClientHelloInfo]
	UserAgentMap   *CachingMap[string, useragent.UserAgent]
	GeoResolver    *GeoResolver
	ForwardHandler HTTPHandler
	TunnelHandler  HTTPHandler
	WebHandler     HTTPHandler
}

type UserInfo struct {
	Username  string
	Password  string
	Attrs     map[string]any
	AuthError error
}

type RequestInfo struct {
	RemoteIP        string
	ServerAddr      string
	ServerName      string
	TLSVersion      TLSVersion
	JA4             string
	ClientHelloInfo *tls.ClientHelloInfo
	ClientHelloRaw  []byte
	ClientTCPConn   *net.TCPConn
	TraceID         log.XID
	UserAgent       useragent.UserAgent
	ProxyUserInfo   UserInfo
	GeoipInfo       GeoipInfo
	LogContext      log.Context
}

var RequestInfoContextKey = struct {
	name string
}{"request-info"}

var riPool = sync.Pool{
	New: func() interface{} {
		return new(RequestInfo)
	},
}

const (
	HTTPTunnelEncryptedPathPrefix  = "/t/20151012/"
	HTTPTunnelConnectTCPPathPrefix = "/.well-known/masque/tcp/"
	HTTPTunnelReverseTCPPathPrefix = "/.well-known/reverse/tcp/"
)

func (h *HTTPServerHandler) Load() error {
	return nil
}

func (h *HTTPServerHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := riPool.Get().(*RequestInfo)
	defer riPool.Put(ri)

	ri.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	ri.ServerAddr = req.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
	if req.TLS != nil {
		ri.ServerName = req.TLS.ServerName
		ri.TLSVersion = TLSVersion(req.TLS.Version)
	} else {
		ri.ServerName = ""
		ri.TLSVersion = 0
	}

	ri.ClientHelloInfo, ri.ClientHelloRaw, ri.ClientTCPConn = nil, nil, nil
	if req.ProtoMajor == 3 {
		if v, ok := req.Context().Value(HTTP3ClientHelloInfoContextKey).(*TLSClientHelloInfo); ok {
			ri.ClientHelloInfo = v.ClientHelloInfo
			ri.JA4 = b2s(v.JA4[:])
		}
	} else {
		if v, ok := h.ClientHelloMap.Load(req.RemoteAddr); ok {
			ri.ClientHelloInfo = v.ClientHelloInfo
			ri.JA4 = b2s(v.JA4[:])
			if header := GetMirrorHeader(ri.ClientHelloInfo.Conn); header != nil {
				ri.ClientHelloRaw = header
			}
			if req.ProtoMajor <= 2 {
				conn := ri.ClientHelloInfo.Conn
				if c, ok := conn.(*tls.Conn); ok && c != nil {
					conn = c.NetConn()
				}
				if c, ok := conn.(*MirrorHeaderConn); ok && c != nil {
					conn = c.Conn
				}
				if tc, ok := conn.(*net.TCPConn); ok && tc != nil {
					ri.ClientTCPConn = tc
				}
			}
		}
	}

	// fix http3 request
	if req.Proto == "" && ri.ClientHelloInfo != nil && len(ri.ClientHelloInfo.SupportedProtos) > 0 && ri.ClientHelloInfo.SupportedProtos[0] == "h3" {
		req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/3.0", 3, 0
	}

	// decode encrypted url
	if strings.HasPrefix(req.RequestURI, HTTPTunnelEncryptedPathPrefix) {
		passphrase := cmp.Or(h.Config.Chacha20Key, HTTPTunnelEncryptedPathPrefix[3:len(HTTPTunnelEncryptedPathPrefix)-1])
		s1, s2, _ := strings.Cut(req.RequestURI[len(HTTPTunnelEncryptedPathPrefix):], "/")
		nonce, err1 := hex.AppendDecode(make([]byte, 0, 32), s2b(s1))
		payload, err2 := base64.StdEncoding.AppendDecode(make([]byte, 0, 2048), s2b(s2))
		if err := cmp.Or(err1, err2); err == nil {
			if cipher, err := Chacha20NewDecryptStreamCipher(s2b(passphrase), nonce); err == nil {
				cipher.XORKeyStream(payload, payload)
				var info struct {
					Time   int64       `json:"time"`
					Header http.Header `json:"header"`
					Method string      `json:"method"`
					URI    string      `json:"uri"`
				}
				if err := json.Unmarshal(payload, &info); err == nil {
					for key, values := range info.Header {
						for _, value := range values {
							req.Header.Add(key, value)
						}
					}
					req.Method = cmp.Or(info.Method, req.Method)
					req.RequestURI = info.URI
					req.URL.Path = req.RequestURI
					req.URL.RawPath = req.RequestURI
				}
			}
		}
	}

	// fix http3 tunnel request
	if req.ProtoMajor == 3 && req.Method == http.MethodConnect {
		if s := req.Header.Get("location"); strings.HasPrefix(s, HTTPTunnelReverseTCPPathPrefix) {
			req.URL.RawPath = s
			req.URL.Path = s
		}
	}

	// fix real remote ip
	if xfr := req.Header.Get("x-forwarded-for"); xfr != "" {
		ri.RemoteIP = strings.Split(xfr, ",")[0]
	}

	ri.UserAgent, _, _ = h.UserAgentMap.Get(req.Header.Get("User-Agent"))
	if h.GeoResolver.CityReader != nil {
		ri.GeoipInfo.Country, ri.GeoipInfo.City, _ = h.GeoResolver.LookupCity(context.Background(), net.ParseIP(ri.RemoteIP))
	}

	ri.ProxyUserInfo = UserInfo{}
	if s := req.Header.Get("proxy-authorization"); s != "" {
		switch t, s, _ := strings.Cut(s, " "); t {
		case "Basic":
			if b, err := base64.StdEncoding.DecodeString(s); err == nil {
				ri.ProxyUserInfo.Username, ri.ProxyUserInfo.Password, _ = strings.Cut(string(b), ":")
			}
		}
	}

	ri.TraceID = log.NewXID()

	ri.LogContext = log.NewContext(ri.LogContext[:0]).
		Xid("trace_id", ri.TraceID).
		Str("server_name", ri.ServerName).
		Str("server_addr", ri.ServerAddr).
		Str("tls_version", ri.TLSVersion.String()).
		Str("ja4", ri.JA4).
		Str("remote_ip", ri.RemoteIP).
		Str("user_agent", req.UserAgent()).
		Str("http_method", req.Method).
		Str("http_proto", req.Proto).
		Str("http_host", req.Host).
		Str("http_request_uri", req.RequestURI).
		Str("http_proxy_authorization", req.Header.Get("proxy-authorization")).
		Str("http_x_forwarded_for", req.Header.Get("x-forwarded-for")).
		Str("http_x_forwarded_user", req.Header.Get("x-forwarded-user")).
		Str("useragent_os", ri.UserAgent.OS+" "+ri.UserAgent.OSVersion).
		Str("useragent_browser", ri.UserAgent.Name+" "+ri.UserAgent.Version).
		Str("remote_country", ri.GeoipInfo.Country).
		Str("remote_city", ri.GeoipInfo.City).
		Value()

	hostname := req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		hostname = h
	}
	containsHostname := slices.Contains(h.ServerNames, hostname) ||
		slices.ContainsFunc(h.ServerNames, func(s string) bool { return s != "" && s[0] == '*' && strings.HasSuffix(hostname, s[1:]) })

	req = req.WithContext(context.WithValue(req.Context(), RequestInfoContextKey, ri))
	switch {
	case hostname != "" && !containsHostname:
		h.ForwardHandler.ServeHTTP(rw, req)
	case containsHostname && strings.HasPrefix(req.URL.Path, HTTPTunnelConnectTCPPathPrefix):
		h.ForwardHandler.ServeHTTP(rw, req)
	case containsHostname && h.Config.Tunnel.Enabled && strings.HasPrefix(req.URL.Path, HTTPTunnelReverseTCPPathPrefix):
		h.TunnelHandler.ServeHTTP(rw, req)
	case req.Method == http.MethodConnect && req.RequestURI[0] != '/':
		h.ForwardHandler.ServeHTTP(rw, req)
	default:
		h.WebHandler.ServeHTTP(rw, req)
	}
}

var csvloaders = xsync.NewMap[string, *FileLoader[[]UserInfo]](xsync.WithSerialResize())

func GetUserCsvLoader(authTableFile string) *FileLoader[[]UserInfo] {
	unmarshal := func(data []byte, v any) error {
		infos, ok := v.(*[]UserInfo)
		if !ok {
			return fmt.Errorf("*[]UserInfo required, found %T", v)
		}
		lines := AppendSplitLines(nil, b2s(data))
		if len(lines) <= 1 {
			return fmt.Errorf("no csv rows: %s", data)
		}
		names := strings.Split(lines[0], ",")
		if len(names) <= 1 {
			return fmt.Errorf("no csv columns: %s", data)
		}
		for i := range names {
			names[i] = strings.ToLower(names[i])
		}
		for _, line := range lines[1:] {
			parts := strings.Split(line, ",")
			if len(parts) <= 1 {
				continue
			}
			var user UserInfo
			for i, part := range parts {
				switch i {
				case 0:
					user.Username = part
				case 1:
					user.Password = part
				default:
					if user.Attrs == nil {
						user.Attrs = make(map[string]any)
					}
					if i >= len(names) {
						return fmt.Errorf("overflow csv cloumn, names=%v parts=%v", names, parts)
					}
					user.Attrs[names[i]] = part
				}
			}
			*infos = append(*infos, user)
		}
		slices.SortFunc(*infos, func(a, b UserInfo) int {
			return cmp.Compare(a.Username, b.Username)
		})
		return nil
	}

	loader, _ := csvloaders.LoadOrCompute(authTableFile, func() (*FileLoader[[]UserInfo], bool) {
		return &FileLoader[[]UserInfo]{
			Filename:     authTableFile,
			Unmarshal:    unmarshal,
			PollDuration: 15 * time.Second,
			Logger:       log.DefaultLogger.Slog(),
		}, false
	})

	return loader
}

func VerifyUserInfoByCsvLoader(csvloader *FileLoader[[]UserInfo], user *UserInfo) error {
	records := *csvloader.Load()
	i, ok := slices.BinarySearchFunc(records, *user, func(a, b UserInfo) int { return cmp.Compare(a.Username, b.Username) })
	switch {
	case !ok:
		user.AuthError = fmt.Errorf("invalid username: %v", user.Username)
	case strings.HasPrefix(records[i].Password, "$2y$") && len(records[i].Password) == 60:
		if err := bcrypt.CompareHashAndPassword([]byte(records[i].Password), []byte(user.Password)); err != nil {
			user.AuthError = err
		} else {
			*user = records[i]
		}
	case user.Password != records[i].Password:
		user.AuthError = fmt.Errorf("wrong password: %v", user.Username)
	default:
		*user = records[i]
	}
	return user.AuthError
}
