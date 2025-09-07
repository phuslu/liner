package main

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
	"github.com/puzpuzpuz/xsync/v4"
)

type HTTPHandler interface {
	http.Handler
	Load() error
}

type HTTPServerHandler struct {
	Config           HTTPConfig
	Hostnames        []string
	HostnameSuffixes []string
	ClientHelloMap   *xsync.Map[PlainAddr, *TLSClientHelloInfo]
	UserAgentMap     *CachingMap[string, useragent.UserAgent]
	GeoResolver      *GeoResolver
	ForwardHandler   HTTPHandler
	TunnelHandler    HTTPHandler
	WebHandler       HTTPHandler
}

type HTTPRequestInfo struct {
	RemoteAddr      netip.AddrPort
	ServerAddr      netip.AddrPort
	TLSServerName   string
	TLSVersion      TLSVersion
	JA4             string
	ClientHelloInfo *tls.ClientHelloInfo
	ClientHelloRaw  []byte
	ClientTCPConn   TCPConn
	ClientQuicConn  QuicConn
	TraceID         log.XID
	UserAgent       useragent.UserAgent
	ProxyUserBytes  []byte
	ProxyUserInfo   AuthUserInfo
	AuthUserBytes   []byte
	AuthUserInfo    AuthUserInfo
	GeoIPInfo       GeoIPInfo
	LogContext      log.Context
	PolicyBuffer    WritableBytes
}

type HTTPContextKey struct {
	name string
}

var HTTPRequestInfoContextKey any = &HTTPContextKey{"http-request-info"}

var hrPool = sync.Pool{
	New: func() interface{} {
		return new(HTTPRequestInfo)
	},
}

const (
	HTTPWellknownBase64PathPrefix  = "/.well-known/base64/"
	HTTPTunnelConnectTCPPathPrefix = "/.well-known/masque/tcp/"
	HTTPTunnelReverseTCPPathPrefix = "/.well-known/reverse/tcp/"
)

func (h *HTTPServerHandler) Load() error {
	return nil
}

func (h *HTTPServerHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := hrPool.Get().(*HTTPRequestInfo)
	defer hrPool.Put(ri)

	ri.RemoteAddr, _ = netip.ParseAddrPort(req.RemoteAddr)
	ri.ServerAddr = AddrPortFromNetAddr(req.Context().Value(http.LocalAddrContextKey).(net.Addr))
	if req.TLS != nil {
		ri.TLSServerName = req.TLS.ServerName
		ri.TLSVersion = TLSVersion(req.TLS.Version)
	} else {
		ri.TLSServerName = ""
		ri.TLSVersion = 0
	}

	ri.ClientHelloInfo, ri.ClientHelloRaw, ri.ClientTCPConn, ri.ClientQuicConn = nil, nil, TCPConn{}, QuicConn{}
	if req.ProtoMajor == 3 {
		if v, ok := req.Context().Value(HTTP3ClientHelloInfoContextKey).(*TLSClientHelloInfo); ok {
			ri.ClientHelloInfo = v.ClientHelloInfo
			ri.ClientQuicConn = QuicConn{v.QuicConn}
			ri.JA4 = b2s(v.JA4[:])
		}
	} else {
		if v, ok := h.ClientHelloMap.Load(PlainAddrFromAddrPort(ri.RemoteAddr)); ok {
			ri.ClientHelloInfo = v.ClientHelloInfo
			ri.JA4 = b2s(v.JA4[:])
			if header := GetMirrorHeader(ri.ClientHelloInfo.Conn); header != nil {
				ri.ClientHelloRaw = header
			}
			conn := v.Conn
			if c, ok := conn.(*tls.Conn); ok && c != nil {
				conn = c.NetConn()
			}
			if c, ok := conn.(*MirrorHeaderConn); ok && c != nil {
				conn = c.Conn
			}
			if tc, ok := conn.(*net.TCPConn); ok && tc != nil {
				ri.ClientTCPConn = TCPConn{tc}
			}
		}
	}

	// decode base64 url
	if strings.HasPrefix(req.RequestURI, HTTPWellknownBase64PathPrefix) {
		payload, err := base64.StdEncoding.AppendDecode(make([]byte, 0, 1024), s2b(req.RequestURI[len(HTTPWellknownBase64PathPrefix):]))
		if err == nil {
			req.RequestURI = string(payload)
			req.URL.Path = req.RequestURI
			req.URL.RawPath = req.RequestURI
		}
	}

	// fix http3 request
	if req.Proto == "" && ri.ClientHelloInfo != nil && len(ri.ClientHelloInfo.SupportedProtos) > 0 && ri.ClientHelloInfo.SupportedProtos[0] == "h3" {
		req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/3.0", 3, 0
	}

	// fix http3 tunnel request
	if req.ProtoMajor == 3 && req.Method == http.MethodConnect {
		if s := req.Header.Get("location"); strings.HasPrefix(s, HTTPTunnelReverseTCPPathPrefix) {
			req.URL.RawPath = s
			req.URL.Path = s
		}
	}

	ri.UserAgent, _, _ = h.UserAgentMap.Get(req.Header.Get("User-Agent"))
	if h.GeoResolver.CityReader != nil {
		ri.GeoIPInfo = h.GeoResolver.GetGeoIPInfo(req.Context(), ri.RemoteAddr.Addr())
	}

	ri.ProxyUserInfo = AuthUserInfo{}
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

	ri.AuthUserInfo = AuthUserInfo{}
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
		NetIPAddrPort("server_addr", ri.ServerAddr).
		Str("tls_server_name", ri.TLSServerName).
		Str("tls_version", ri.TLSVersion.String()).
		Str("ja4", ri.JA4).
		NetIPAddr("remote_ip", ri.RemoteAddr.Addr()).
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
		Str("remote_country", ri.GeoIPInfo.Country).
		Str("remote_city", ri.GeoIPInfo.City).
		Str("remote_isp", ri.GeoIPInfo.ISP).
		Str("remote_connection_type", ri.GeoIPInfo.ConnectionType).
		Value()

	ri.PolicyBuffer.Reset()

	req = req.WithContext(context.WithValue(req.Context(), HTTPRequestInfoContextKey, ri))

	hostname := req.Host
	if s, _, err := net.SplitHostPort(req.Host); err == nil {
		hostname = s
	}

	matched := slices.Contains(h.Hostnames, hostname)
	if !matched && len(h.HostnameSuffixes) != 0 {
		for _, suffix := range h.HostnameSuffixes {
			if strings.HasSuffix(hostname, suffix) {
				matched = true
				break
			}
		}
	}

	switch {
	case hostname != "" && !matched:
		h.ForwardHandler.ServeHTTP(rw, req)
	case matched && strings.HasPrefix(req.URL.Path, HTTPTunnelConnectTCPPathPrefix):
		h.ForwardHandler.ServeHTTP(rw, req)
	case matched && h.Config.Tunnel.Enabled && strings.HasPrefix(req.URL.Path, HTTPTunnelReverseTCPPathPrefix):
		h.TunnelHandler.ServeHTTP(rw, req)
	case req.Method == http.MethodConnect && req.RequestURI[0] != '/':
		h.ForwardHandler.ServeHTTP(rw, req)
	default:
		h.WebHandler.ServeHTTP(rw, req)
	}
}
