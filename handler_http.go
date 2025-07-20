package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/zeebo/wyhash"
	"golang.org/x/crypto/argon2"
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
	Username string
	Password string
	Attrs    map[string]any
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
	ProxyUserBytes  []byte
	ProxyUserInfo   UserInfo
	AuthUserBytes   []byte
	AuthUserInfo    UserInfo
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
			var err error
			if ri.ProxyUserBytes, err = base64.StdEncoding.AppendDecode(ri.ProxyUserBytes[:0], s2b(s)); err == nil {
				if i := bytes.IndexByte(ri.ProxyUserBytes, ':'); i > 0 {
					ri.ProxyUserInfo.Username = b2s(ri.ProxyUserBytes[:i])
					ri.ProxyUserInfo.Password = b2s(ri.ProxyUserBytes[i+1:])
				}
			}
		}
	}

	ri.AuthUserInfo = UserInfo{}
	if s := req.Header.Get("authorization"); s != "" {
		switch t, s, _ := strings.Cut(s, " "); t {
		case "Basic":
			var err error
			if ri.AuthUserBytes, err = base64.StdEncoding.AppendDecode(ri.AuthUserBytes[:0], s2b(s)); err == nil {
				if i := bytes.IndexByte(ri.AuthUserBytes, ':'); i > 0 {
					ri.AuthUserInfo.Username = b2s(ri.AuthUserBytes[:i])
					ri.AuthUserInfo.Password = b2s(ri.AuthUserBytes[i+1:])
				}
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

var usercsvloaders = xsync.NewMap[string, *FileLoader[[]UserInfo]](xsync.WithSerialResize())

func GetUserInfoCsvLoader(authTableFile string) (loader *FileLoader[[]UserInfo]) {
	loader, _ = usercsvloaders.LoadOrCompute(authTableFile, func() (*FileLoader[[]UserInfo], bool) {
		return &FileLoader[[]UserInfo]{
			Filename:     authTableFile,
			PollDuration: 15 * time.Second,
			Logger:       log.DefaultLogger.Slog(),
			Unmarshal: func(data []byte, v any) error {
				infos, ok := v.(*[]UserInfo)
				if !ok {
					return fmt.Errorf("*[]UserInfo required, found %T", v)
				}

				records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
				if err != nil {
					return err
				}
				if len(records) <= 1 {
					return fmt.Errorf("no csv rows in %q", data)
				}

				names := records[0]
				for _, parts := range records[1:] {
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
			},
		}, false
	})
	return
}

var argon2idRegex = regexp.MustCompile(`^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$(.+)\$(.+)$`)

func LookupUserInfoFromCsvLoader(userloader *FileLoader[[]UserInfo], user *UserInfo) (err error) {
	records := *userloader.Load()
	i, ok := slices.BinarySearchFunc(records, *user, func(a, b UserInfo) int { return cmp.Compare(a.Username, b.Username) })
	switch {
	case !ok:
		err = fmt.Errorf("invalid username: %v", user.Username)
	case user.Password == records[i].Password:
		*user = records[i]
	case strings.HasPrefix(records[i].Password, "0x"):
		var b []byte
		b, err = hex.AppendDecode(make([]byte, 0, 64), s2b(records[i].Password[2:]))
		if err != nil {
			err = fmt.Errorf("invalid sha1/sha256 password: %v", records[i].Password)
			return
		}
		switch len(b) {
		case 8:
			if binary.BigEndian.Uint64(b) == wyhash.HashString(user.Password, 0) {
				*user = records[i]
				return
			}
		case 20:
			if *(*[20]byte)(b) == sha1.Sum(s2b(user.Password)) {
				*user = records[i]
				return
			}
		case 32:
			if *(*[32]byte)(b) == sha256.Sum256(s2b(user.Password)) {
				*user = records[i]
				return
			}
		}
		err = fmt.Errorf("invalid md5/sha1/sha256 password: %v", records[i].Password)
		return
	case strings.HasPrefix(records[i].Password, "$2y$"):
		err = bcrypt.CompareHashAndPassword([]byte(records[i].Password), []byte(user.Password))
		if err == nil {
			*user = records[i]
		} else {
			err = fmt.Errorf("wrong password: %v: %w", user.Username, err)
		}
	case strings.HasPrefix(records[i].Password, "$argon2id$"):
		// see https://github.com/alexedwards/argon2id
		// $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
		ms := argon2idRegex.FindStringSubmatch(records[i].Password)
		if ms == nil {
			err = fmt.Errorf("invalid argon2id password: %v", records[i].Password)
			return
		}
		m, t, p := first(strconv.Atoi(ms[2])), first(strconv.Atoi(ms[3])), first(strconv.Atoi(ms[4]))
		var salt, key []byte
		salt, err = base64.RawStdEncoding.Strict().DecodeString(ms[5])
		if err != nil {
			err = fmt.Errorf("invalid argon2id password: %v : %w", records[i].Password, err)
			return
		}
		key, err = base64.RawStdEncoding.Strict().DecodeString(ms[6])
		if err != nil {
			err = fmt.Errorf("invalid argon2id password: %v : %w", records[i].Password, err)
			return
		}
		idkey := argon2.IDKey([]byte(user.Password), salt, uint32(t), uint32(m), uint8(p), uint32(len(key)))
		if subtle.ConstantTimeEq(int32(len(key)), int32(len(idkey))) == 0 ||
			subtle.ConstantTimeCompare(key, idkey) != 1 {
			err = fmt.Errorf("wrong password: %v", user.Username)
		}
	default:
		err = fmt.Errorf("wrong password: %v", user.Username)
	}
	return
}
