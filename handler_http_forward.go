package main

import (
	"cmp"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/net/publicsuffix"
)

type HTTPForwardHandler struct {
	Config          HTTPConfig
	DataLogger      log.Logger
	MemoryListeners *sync.Map // map[string]*MemoryListener
	MemoryDialers   *sync.Map // map[string]*MemoryDialer
	LocalDialer     *LocalDialer
	LocalTransport  *http.Transport
	Dialers         map[string]Dialer
	DialerURLs      map[string]string
	GeoResolver     *GeoResolver
	Functions       template.FuncMap

	policy        *template.Template
	tcpcongestion *template.Template
	dialer        *template.Template
	transports    map[string]*http.Transport
	userchecker   AuthUserChecker
}

func (h *HTTPForwardHandler) Load() error {
	var err error

	h.Config.Forward.Policy = strings.TrimSpace(h.Config.Forward.Policy)
	if s := h.Config.Forward.Policy; strings.Contains(s, "{{") {
		if h.policy, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	h.Config.Forward.TcpCongestion = strings.TrimSpace(h.Config.Forward.TcpCongestion)
	if s := h.Config.Forward.TcpCongestion; strings.Contains(s, "{{") {
		if h.tcpcongestion, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	h.Config.Forward.Dialer = strings.TrimSpace(h.Config.Forward.Dialer)
	if s := h.Config.Forward.Dialer; strings.Contains(s, "{{") {
		if h.dialer, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if len(h.Dialers) != 0 {
		h.transports = make(map[string]*http.Transport)
		for name, dailer := range h.Dialers {
			h.transports[name] = &http.Transport{
				DialContext:         dailer.DialContext,
				TLSClientConfig:     h.LocalTransport.TLSClientConfig,
				TLSHandshakeTimeout: h.LocalTransport.TLSHandshakeTimeout,
				IdleConnTimeout:     h.LocalTransport.IdleConnTimeout,
				DisableCompression:  h.LocalTransport.DisableCompression,
				MaxIdleConns:        32,
			}
		}
	}

	if strings.HasSuffix(h.Config.Forward.AuthTable, ".csv") {
		csvloader := &AuthUserCSVLoader{Filename: h.Config.Forward.AuthTable}
		records, err := csvloader.LoadAuthUsers(context.Background())
		if err != nil {
			log.Fatal().Err(err).Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Forward.AuthTable).Msg("load auth_table failed")
		}
		log.Info().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Forward.AuthTable).Int("auth_table_size", len(records)).Msg("load auth_table ok")
		h.userchecker = &AuthUserLoadChecker{csvloader}
	}

	return nil
}

func (h *HTTPForwardHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	// fix real remote ip
	// if xfr := req.Header.Get("x-forwarded-for"); xfr != "" {
	// 	ri.RemoteIP = strings.Split(xfr, ",")[0]
	// }

	tunnel := strings.HasPrefix(req.URL.Path, HTTPTunnelConnectTCPPathPrefix)
	if tunnel {
		// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-connect-tcp-05
		parts := strings.Split(req.URL.Path, "/")
		hostport := net.JoinHostPort(parts[len(parts)-3], parts[len(parts)-2])

		// fix up request
		req.Host = hostport
		req.URL = &url.URL{Host: req.Host}
		req.Method = http.MethodConnect
	}

	var err error
	var host = req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		host = h
	}

	geosite := h.GeoResolver.GetGeoSiteInfo(req.Context(), host)

	var domain string
	if ip := net.ParseIP(host); ip == nil {
		if s, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
			domain = s
		} else {
			domain = host
		}
	} else {
		domain = req.Host
	}

	if h.Config.Forward.Policy == "" {
		http.NotFound(rw, req)
		return
	}

	var proxyAuthError error
	if h.userchecker != nil && ri.ProxyUserInfo.Username != "" {
		proxyAuthError = h.userchecker.CheckAuthUser(req.Context(), &ri.ProxyUserInfo)
	}

	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	policyName := h.Config.Forward.Policy
	speedLimit := h.Config.Forward.SpeedLimit
	if h.policy != nil {
		bb.Reset()
		err = h.policy.Execute(bb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			JA4             string
			User            AuthUserInfo
			UserAgent       *useragent.UserAgent
			ServerAddr      netip.AddrPort
		}{req, ri.ClientHelloInfo, ri.JA4, ri.ProxyUserInfo, &ri.UserAgent, ri.ServerAddr})
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("forward_policy", h.Config.Forward.Policy).Interface("client_hello_info", ri.ClientHelloInfo).Interface("tls_connection_state", req.TLS).Msg("execute forward_policy error")
			http.NotFound(rw, req)
			return
		}

		policyName = strings.TrimSpace(bb.String())
		log.Debug().Context(ri.LogContext).Interface("client_hello_info", ri.ClientHelloInfo).Interface("tls_connection_state", req.TLS).Str("forward_policy_name", policyName).Msg("execute forward_policy ok")

		switch policyName {
		case "", "proxy_pass":
			http.NotFound(rw, req)
			return
		case "reject", "deny":
			RejectRequest(rw, req)
			return
		case "reset", "close":
			if conn, _, err := http.NewResponseController(rw).Hijack(); err == nil {
				conn.Close()
			}
			return
		case "require_auth", "require_proxy_auth", "require_www_auth":
			var authCode int
			var authHeader, authText string
			switch policyName {
			case "require_www_auth":
				authCode = http.StatusUnauthorized
				authHeader = "www-authenticate"
				authText = "Authentication Required"
			default:
				authCode = http.StatusProxyAuthRequired
				authHeader = "proxy-authenticate"
				authText = "Authentication Required"
			}
			resp := &http.Response{
				StatusCode: authCode,
				Header: http.Header{
					"content-type": []string{"text/plain; charset=UTF-8"},
					authHeader:     []string{fmt.Sprintf("Basic realm=\"%s\"", authText)},
				},
				Request:       req,
				ContentLength: int64(len(authText)),
				Body:          io.NopCloser(strings.NewReader(authText)),
			}
			for key, values := range resp.Header {
				for _, value := range values {
					rw.Header().Add(key, value)
				}
			}
			rw.WriteHeader(resp.StatusCode)
			io.Copy(rw, resp.Body)
			return
		}
	}

	if policyName != "bypass_auth" && (ri.ProxyUserInfo.Username == "" || proxyAuthError != nil) {
		log.Warn().Err(err).Context(ri.LogContext).Str("username", ri.ProxyUserInfo.Username).Str("proxy_authorization", req.Header.Get("proxy-authorization")).Msg("auth error")
		RejectRequest(rw, req)
		return
	}

	if allow := ri.ProxyUserInfo.Attrs["allow_client"]; allow != "" && allow != "1" {
		browser := strings.HasPrefix(req.UserAgent(), "Mozilla/5.0 ")
		if ri.ClientHelloInfo != nil && len(ri.ClientHelloInfo.CipherSuites) != 0 {
			if c := ri.ClientHelloInfo.CipherSuites[0]; !(c&0x0f0f == 0x0a0a && c&0xff == c>>8) {
				browser = false
			}
		}
		if !browser {
			log.Warn().Err(err).Context(ri.LogContext).Str("username", ri.ProxyUserInfo.Username).Str("proxy_authorization", req.Header.Get("proxy-authorization")).Msg("user is not allow client")
			RejectRequest(rw, req)
			return
		}
	}

	if s := ri.ProxyUserInfo.Attrs["speed_limit"]; s != "" {
		n, _ := strconv.ParseInt(s, 10, 64)
		switch {
		case n > 0:
			speedLimit = n
		case n < 0:
			speedLimit = 0 // privileged users has no speed_limit
		}
	}

	// eval tcp_congestion template
	if ri.ClientTCPConn != nil && h.Config.Forward.TcpCongestion != "" {
		var tcpCongestion = h.Config.Forward.TcpCongestion
		if h.tcpcongestion != nil {
			bb.Reset()
			err := h.tcpcongestion.Execute(bb, struct {
				Request         *http.Request
				ClientHelloInfo *tls.ClientHelloInfo
				JA4             string
				UserAgent       *useragent.UserAgent
				ServerAddr      netip.AddrPort
				User            AuthUserInfo
			}{req, ri.ClientHelloInfo, ri.JA4, &ri.UserAgent, ri.ServerAddr, ri.ProxyUserInfo})
			if err != nil {
				log.Error().Err(err).Context(ri.LogContext).Str("forward_tcp_congestion", h.Config.Forward.TcpCongestion).Msg("execute forward_tcp_congestion error")
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			tcpCongestion = bb.String()
		}
		if options := strings.Fields(tcpCongestion); len(options) >= 1 {
			switch name := options[0]; name {
			case "brutal":
				if len(options) < 2 {
					log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("parse forward_tcp_congestion error")
					http.Error(rw, err.Error(), http.StatusBadGateway)
					return
				}
				if rate, _ := strconv.Atoi(options[1]); rate > 0 {
					gain := 20 // hysteria2 default
					if len(options) >= 3 {
						if n, _ := strconv.Atoi(options[2]); n > 0 {
							gain = n
						}
					}
					if err := SetTcpCongestion(ri.ClientTCPConn, name, uint64(rate), uint32(gain)); err != nil {
						log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion error")
						http.Error(rw, err.Error(), http.StatusBadGateway)
						return
					}
					log.Debug().NetIPAddr("remote_ip", ri.RemoteAddr.Addr()).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion ok")
				}
			default:
				if err := SetTcpCongestion(ri.ClientTCPConn, name); err != nil {
					log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion error")
					http.Error(rw, err.Error(), http.StatusBadGateway)
					return
				}
			}
		}
	}

	if ri.ClientTCPConn != nil && speedLimit > 0 {
		err := SetTcpMaxPacingRate(ri.ClientTCPConn, int(speedLimit))
		log.DefaultLogger.Err(err).Context(ri.LogContext).Int64("forward_speedlimit", speedLimit).Msg("set forward_speedlimit")
	}

	var dialerValue = h.Config.Forward.Dialer
	if h.dialer != nil {
		bb.Reset()
		err := h.dialer.Execute(bb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			JA4             string
			UserAgent       *useragent.UserAgent
			ServerAddr      netip.AddrPort
			User            AuthUserInfo
		}{req, ri.ClientHelloInfo, ri.JA4, &ri.UserAgent, ri.ServerAddr, ri.ProxyUserInfo})
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute forward_dialer error")
			http.NotFound(rw, req)
			return
		}
		dialerValue = strings.TrimSpace(bb.String())
	}

	var userLog = h.Config.Forward.Log
	if ri.ProxyUserInfo.Attrs["no_log"] == "1" {
		userLog = false
	}

	log.Info().Context(ri.LogContext).Str("req_method", req.Method).Str("req_host", req.Host).Str("geosite", geosite.Site).Any("req_header", req.Header).Str("username", ri.ProxyUserInfo.Username).Any("user_attrs", ri.ProxyUserInfo.Attrs).Str("forward_policy_name", policyName).Str("forward_dialer_value", dialerValue).Str("http_domain", domain).Int64("speed_limit", speedLimit).Msg("forward request")

	var dialerName = dialerValue
	var preferIPv6 = h.Config.Forward.PreferIpv6
	if strings.Contains(dialerValue, "=") {
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("username", ri.ProxyUserInfo.Username).Str("forward_policy_name", policyName).Str("forward_dialer_value", dialerValue).Str("http_domain", domain).Msg("forward parse dialer json error")
			return
		}
		dialerName = u.Get("dialer")
		if s := u.Get("prefer_ipv6"); s != "" {
			preferIPv6, _ = strconv.ParseBool(s)
		}
	}

	switch req.Method {
	case http.MethodConnect:
		if req.URL.Host == ri.TLSServerName {
			// FIXME: handle self-connect clients
		}

		if h.MemoryListeners != nil {
			if v, ok := h.MemoryListeners.Load(req.Host); ok && v != nil {
				ln, _ := v.(*MemoryListener)
				switch req.ProtoMajor {
				case 1:
					lconn, _, err := http.NewResponseController(rw).Hijack()
					if err != nil {
						http.Error(rw, err.Error(), http.StatusBadGateway)
						return
					}
					io.WriteString(lconn, "HTTP/1.1 200 OK\r\n\r\n")
					ln.SendConn(lconn)
					log.Info().Context(ri.LogContext).NetAddr("memory_listener_addr", ln.Addr()).Msg("http forward handler memory listener local addr")
					return
				case 2:
					rw.WriteHeader(http.StatusOK)
					ln.SendConn(HTTPRequestStream{req.Body, rw, http.NewResponseController(rw), net.TCPAddrFromAddrPort(ri.RemoteAddr), net.TCPAddrFromAddrPort(ri.ServerAddr)})
					log.Info().Context(ri.LogContext).NetAddr("memory_listener_addr", ln.Addr()).Msg("http2 forward handler memory listener local addr")
					return
				}
			}
		}

		var dialer Dialer
		if dialerName != "" {
			if d, ok := h.Dialers[dialerName]; !ok {
				log.Error().Context(ri.LogContext).Str("dialer", dialerName).Msg("no dialer exists")
				http.NotFound(rw, req)
				return
			} else {
				dialer = d
			}
		} else {
			dialer = h.LocalDialer
		}

		ctx := req.Context()
		if preferIPv6 {
			ctx = context.WithValue(ctx, DialerPreferIPv6ContextKey, struct{}{})
		}
		if h.MemoryDialers != nil {
			ctx = context.WithValue(ctx, DialerMemoryDialersContextKey, h.MemoryDialers)
		}
		if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
			if s := header.Get("x-forwarded-for"); s != "" {
				header.Set("x-forwarded-for", s+","+ri.RemoteAddr.Addr().String())
			} else {
				header.Set("x-forwarded-for", ri.RemoteAddr.Addr().String())
			}
			if s := header.Get("x-forwarded-user"); s != "" {
				header.Set("x-forwarded-user", s+","+ri.ProxyUserInfo.Username)
			} else {
				header.Set("x-forwarded-user", ri.ProxyUserInfo.Username)
			}
		} else {
			ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
				"x-forwarded-for":  []string{ri.RemoteAddr.Addr().String()},
				"x-forwarded-user": []string{ri.ProxyUserInfo.Username},
			})
		}
		network := cmp.Or(req.Header.Get("x-forwarded-network"), "tcp")
		conn, err := dialer.DialContext(ctx, network, req.Host)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Msg("dial host error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		log.Debug().Context(ri.LogContext).Str("geosite", geosite.Site).Any("req_header", req.Header).NetAddr("conn_remote_addr", conn.RemoteAddr()).Msg("dial host ok")

		var w io.Writer
		var r io.Reader

		if req.ProtoAtLeast(2, 0) {
			if tunnel && req.Header.Get("Sec-Websocket-Key") != "" {
				key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				rw.Header().Set("sec-websocket-accept", base64.StdEncoding.EncodeToString(key[:]))
				rw.Header().Set("upgrade", "websocket")
				rw.Header().Set("connection", "Upgrade")
				rw.WriteHeader(http.StatusSwitchingProtocols)
			} else {
				rw.WriteHeader(http.StatusOK)
			}
			http.NewResponseController(rw).Flush()

			w = HTTPFlushWriter{rw, http.NewResponseController(rw)}
			r = req.Body
		} else {
			lconn, _, err := http.NewResponseController(rw).Hijack()
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			defer lconn.Close()

			w = lconn
			r = lconn

			if tunnel {
				key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				fmt.Fprintf(lconn, "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", base64.StdEncoding.EncodeToString(key[:]))
			} else {
				io.WriteString(lconn, "HTTP/1.1 200 OK\r\n\r\n")
			}
		}

		defer conn.Close()

		go io.Copy(conn, r)

		if userLog {
			w = &DataLogWriter{
				Writer:     w,
				DataLogger: h.DataLogger,
				Context: log.NewContext(nil).
					Str("logger", "forward").
					Xid("trace_id", ri.TraceID).
					NetIPAddrPort("server_addr", ri.ServerAddr).
					Str("tls_server_name", ri.TLSServerName).
					Str("tls_version", ri.TLSVersion.String()).
					Str("ja4", ri.JA4).
					Str("username", ri.ProxyUserInfo.Username).
					NetIPAddr("remote_ip", ri.RemoteAddr.Addr()).
					Str("remote_country", ri.GeoIPInfo.Country).
					Str("remote_city", ri.GeoIPInfo.City).
					Str("remote_isp", ri.GeoIPInfo.ISP).
					Str("remote_connection_type", ri.GeoIPInfo.ConnectionType).
					Str("http_proto", req.Proto).
					Str("http_method", req.Method).
					Str("http_host", host).
					Str("http_domain", domain).
					Str("geosite", geosite.Site).
					Str("user_agent", req.UserAgent()).
					Str("user_agent_os", ri.UserAgent.OS).
					Str("user_agent_os_version", ri.UserAgent.OSVersion).
					Str("user_agent_name", ri.UserAgent.Name).
					Str("user_agent_version", ri.UserAgent.Version).
					Int64("speed_limit", speedLimit).
					Value(),
				FieldName: "transmit_bytes",
				Interval:  cmp.Or(h.Config.Forward.LogInterval, 1),
			}
		}
		var transmitBytes int64
		if tc, ok := conn.(*net.TCPConn); ok && req.ProtoAtLeast(2, 0) {
			// Use wrapper to hide existing w.WriteTo from io.Copy.
			// buffer size should align to http2.MaxReadFrameSize
			if n := h.Config.Forward.IoCopyBuffer; n > 0 {
				transmitBytes, err = io.CopyBuffer(w, tcpConnWithoutWriteTo{TCPConn: tc}, make([]byte, n))
			} else {
				transmitBytes, err = io.Copy(w, tcpConnWithoutWriteTo{TCPConn: tc})
			}
		} else {
			transmitBytes, err = io.Copy(w, conn) // splice to
		}
		log.Debug().Context(ri.LogContext).Str("geosite", geosite.Site).Str("username", ri.ProxyUserInfo.Username).Str("http_domain", domain).Int64("speed_limit", speedLimit).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
	default:
		if req.Host == "" {
			http.NotFound(rw, req)
			return
		}

		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}

		if req.ContentLength == 0 {
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			req.Body = nil
		}

		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}

		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}

		h2 := req.ProtoAtLeast(2, 0)
		if h2 {
			req.ProtoMajor = 1
			req.ProtoMinor = 1
			req.Proto = "HTTP/1.1"
		}

		var tr *http.Transport
		if dialerName != "" {
			if t, ok := h.transports[dialerName]; !ok {
				log.Error().Context(ri.LogContext).Str("dialer", dialerName).Msg("no dialer transport exists")
				http.NotFound(rw, req)
				return
			} else {
				tr = t
			}
		} else {
			tr = h.LocalTransport
		}

		resp, err := tr.RoundTrip(req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		if h2 {
			resp.Header.Del("connection")
			resp.Header.Del("keep-alive")
		}

		for k, vv := range resp.Header {
			for _, v := range vv {
				rw.Header().Add(k, v)
			}
		}
		rw.Header().Set("connection", "close")

		rw.WriteHeader(resp.StatusCode)
		defer resp.Body.Close()

		var w io.Writer = rw
		if userLog {
			w = &DataLogWriter{
				Writer:     w,
				DataLogger: h.DataLogger,
				Context: log.NewContext(nil).
					Str("logger", "forward").
					Xid("trace_id", ri.TraceID).
					NetIPAddrPort("server_addr", ri.ServerAddr).
					Str("tls_server_name", ri.TLSServerName).
					Str("tls_version", ri.TLSVersion.String()).
					Str("ja4", ri.JA4).
					Str("username", ri.ProxyUserInfo.Username).
					NetIPAddr("remote_ip", ri.RemoteAddr.Addr()).
					Str("remote_country", ri.GeoIPInfo.Country).
					Str("remote_city", ri.GeoIPInfo.City).
					Str("remote_isp", ri.GeoIPInfo.ISP).
					Str("remote_connection_type", ri.GeoIPInfo.ConnectionType).
					Str("http_proto", req.Proto).
					Str("http_method", req.Method).
					Str("http_host", host).
					Str("http_domain", domain).
					Str("geosite", geosite.Site).
					Str("user_agent", req.UserAgent()).
					Str("user_agent_os", ri.UserAgent.OS).
					Str("user_agent_os_version", ri.UserAgent.OSVersion).
					Str("user_agent_name", ri.UserAgent.Name).
					Str("user_agent_version", ri.UserAgent.Version).
					Int64("speed_limit", speedLimit).
					Value(),
				FieldName: "transmit_bytes",
				Interval:  cmp.Or(h.Config.Forward.LogInterval, 1),
			}
		}

		transmitBytes, err := io.CopyBuffer(w, resp.Body, make([]byte, 256*1024)) // buffer size should align to http2.MaxReadFrameSize
		log.Debug().Context(ri.LogContext).Str("geosite", geosite.Site).Str("username", ri.ProxyUserInfo.Username).Str("http_domain", domain).Int64("transmit_bytes", transmitBytes).Int64("speed_limit", speedLimit).Err(err).Msg("forward log")
	}
}

func RejectRequest(rw http.ResponseWriter, req *http.Request) {
	time.Sleep(time.Duration(1+fastrandn(3)) * time.Second)
	// http.Error(rw, "403 Forbidden", http.StatusForbidden)
	http.Error(rw, "400 Bad Request", http.StatusBadRequest)
}

// see https://github.com/golang/go/blob/master/src/net/net.go#L785C1-L791C2
type noWriteTo struct{}

func (noWriteTo) WriteTo(io.Writer) (int64, error) {
	panic("can't happen")
}

type tcpConnWithoutWriteTo struct {
	noWriteTo
	*net.TCPConn
}

type DataLogWriter struct {
	io.Writer
	DataLogger log.Logger
	Context    log.Context
	FieldName  string
	Interval   int64

	timestamp int64
	transmits int64
}

func (w *DataLogWriter) Write(buf []byte) (n int, err error) {
	n, err = w.Writer.Write(buf)
	now := time.Now().Unix()
	if w.transmits != 0 && (w.timestamp == 0 || now-w.timestamp >= w.Interval || err != nil) {
		w.DataLogger.Log().Context(w.Context).Int64(w.FieldName, w.transmits).Msg("")
		w.timestamp = now
		w.transmits = 0
	} else {
		w.transmits += int64(n)
	}
	return
}
