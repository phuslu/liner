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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/jszwec/csvutil"
	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/publicsuffix"
)

type HTTPForwardHandler struct {
	Config         HTTPConfig
	ForwardLogger  log.Logger
	LocalDialer    *LocalDialer
	LocalTransport *http.Transport
	Dialers        map[string]Dialer
	Functions      template.FuncMap

	policy        *template.Template
	tcpcongestion *template.Template
	dialer        *template.Template
	transports    map[string]*http.Transport
	csvloader     *FileLoader[[]ForwardAuthInfo]
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
		h.csvloader = &FileLoader[[]ForwardAuthInfo]{
			Filename:     h.Config.Forward.AuthTable,
			Unmarshal:    csvutil.Unmarshal,
			PollDuration: 15 * time.Second,
			ErrorLogger:  log.DefaultLogger.Std("", 0),
		}
		records := h.csvloader.Load()
		if records == nil {
			log.Fatal().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Forward.AuthTable).Msg("load auth_table failed")
		}
		log.Info().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Forward.AuthTable).Int("auth_table_size", len(*records)).Msg("load auth_table ok")
	}

	return nil
}

func (h *HTTPForwardHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	websocket := h.Config.Forward.Websocket != "" && req.URL.Path == h.Config.Forward.Websocket && ((req.Method == http.MethodGet && req.ProtoMajor == 1) || (req.Method == http.MethodConnect && req.ProtoAtLeast(2, 0)))
	if websocket {
		host, port := req.URL.Query().Get("host"), req.URL.Query().Get("port")
		if host == "" && port == "" {
			host, port = req.URL.Query().Get("h"), req.URL.Query().Get("p")
		}
		req.Host = net.JoinHostPort(host, port)
		req.URL = &url.URL{Host: req.Host}
		req.Method = http.MethodConnect
	}

	var err error
	var host = req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		host = h
	}

	var domain = host
	if net.ParseIP(domain) == nil {
		if s, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
			domain = s
		}
	}

	if h.Config.Forward.Policy == "" {
		http.NotFound(rw, req)
		return
	}

	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	var policyName = h.Config.Forward.Policy
	bypassAuth := false
	if h.policy != nil {
		bb.Reset()
		err = h.policy.Execute(bb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			UserAgent       *useragent.UserAgent
			ServerAddr      string
		}{req, ri.ClientHelloInfo, &ri.UserAgent, ri.ServerAddr})
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
			if hijacker, ok := rw.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					conn.Close()
				}
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
		case "bypass_auth":
			bypassAuth = true
		}
	}

	var ai ForwardAuthInfo
	if h.Config.Forward.AuthTable != "" && !bypassAuth {
		ai, err = h.GetAuthInfo(ri, req)
		if err != nil {
			log.Warn().Err(err).Context(ri.LogContext).Str("username", ai.Username).Str("proxy_authorization", req.Header.Get("proxy-authorization")).Msg("auth error")
			RejectRequest(rw, req)
			return
		}
	}

	if ai.VIP == 0 {
		if ai.SpeedLimit == 0 && h.Config.Forward.SpeedLimit > 0 {
			ai.SpeedLimit = h.Config.Forward.SpeedLimit
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
				UserAgent       *useragent.UserAgent
				ServerAddr      string
				User            ForwardAuthInfo
			}{req, ri.ClientHelloInfo, &ri.UserAgent, ri.ServerAddr, ai})
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
					log.Debug().Str("remote_ip", ri.RemoteIP).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion ok")
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

	var dialerName = h.Config.Forward.Dialer
	if h.dialer != nil {
		bb.Reset()
		err := h.dialer.Execute(bb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			UserAgent       *useragent.UserAgent
			ServerAddr      string
			User            ForwardAuthInfo
		}{req, ri.ClientHelloInfo, &ri.UserAgent, ri.ServerAddr, ai})
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute forward_dialer error")
			http.NotFound(rw, req)
			return
		}
		dialerName = strings.TrimSpace(bb.String())
	}

	log.Info().Context(ri.LogContext).Str("username", ai.Username).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Str("http_domain", domain).Msg("forward request")

	var transmitBytes int64
	switch req.Method {
	case http.MethodConnect:
		if req.URL.Host == ri.ServerName {
			// FIXME: handle self-connect clients
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
		if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
			if s := header.Get("x-forwarded-for"); s != "" {
				header.Set("x-forwarded-for", s+","+ri.RemoteIP)
			} else {
				header.Set("x-forwarded-for", ri.RemoteIP)
			}
			if s := header.Get("x-forwarded-user"); s != "" {
				header.Set("x-forwarded-user", s+","+ai.Username)
			} else {
				header.Set("x-forwarded-user", ai.Username)
			}
		} else {
			ctx = context.WithValue(req.Context(), DialerHTTPHeaderContextKey, http.Header{
				"x-forwarded-for":  []string{ri.RemoteIP},
				"x-forwarded-user": []string{ai.Username},
			})
		}
		network := cmp.Or(req.Header.Get("x-forwarded-network"), "tcp")
		conn, err := dialer.DialContext(ctx, network, req.Host)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Msg("dial host error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		var w io.Writer
		var r io.Reader

		if req.ProtoAtLeast(2, 0) {
			flusher, ok := rw.(http.Flusher)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Flusher", rw), http.StatusBadGateway)
				return
			}

			if websocket {
				key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				rw.Header().Set("sec-websocket-accept", string(key[:]))
				rw.Header().Set("upgrade", "websocket")
				rw.Header().Set("connection", "Upgrade")
				rw.WriteHeader(http.StatusSwitchingProtocols)
			} else {
				rw.WriteHeader(http.StatusOK)
			}
			flusher.Flush()

			w = FlushWriter{rw}
			r = req.Body
		} else {
			hijacker, ok := rw.(http.Hijacker)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Hijacker", rw), http.StatusBadGateway)
				return
			}
			lconn, _, err := hijacker.Hijack()
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			defer lconn.Close()

			w = lconn
			r = lconn

			if websocket {
				key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				fmt.Fprintf(lconn, "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", key[:])
			} else {
				io.WriteString(lconn, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
			}
		}

		defer conn.Close()

		go io.Copy(conn, r)

		if h.Config.Forward.Log {
			w = &ForwardLogWriter{
				Writer: w,
				Logger: h.ForwardLogger,
				Context: log.NewContext(nil).
					Xid("trace_id", ri.TraceID).
					Str("server_name", ri.ServerName).
					Str("server_addr", ri.ServerAddr).
					Str("tls_version", ri.TLSVersion.String()).
					Str("username", ai.Username).
					Str("remote_ip", ri.RemoteIP).
					Str("remote_country", ri.GeoipInfo.Country).
					Str("remote_region", ri.GeoipInfo.Region).
					Str("remote_city", ri.GeoipInfo.City).
					Str("http_method", req.Method).
					Str("http_host", host).
					Str("http_domain", domain).
					Str("http_proto", req.Proto).
					Str("user_agent", req.UserAgent()).
					Str("user_agent_os", ri.UserAgent.OS).
					Str("user_agent_os_version", ri.UserAgent.OSVersion).
					Str("user_agent_name", ri.UserAgent.Name).
					Str("user_agent_version", ri.UserAgent.Version).
					Value(),
				FieldName: "transmit_bytes",
				Interval:  cmp.Or(h.Config.Forward.LogInterval, 1),
			}
		}
		transmitBytes, err = io.CopyBuffer(w, NewRateLimitReader(conn, ai.SpeedLimit), make([]byte, 1024*1024)) // buffer size should align to http2.MaxReadFrameSize
		log.Debug().Context(ri.LogContext).Str("username", ai.Username).Str("http_domain", domain).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
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
		if h.Config.Forward.Log {
			w = &ForwardLogWriter{
				Writer: w,
				Logger: h.ForwardLogger,
				Context: log.NewContext(nil).
					Xid("trace_id", ri.TraceID).
					Str("server_name", ri.ServerName).
					Str("server_addr", ri.ServerAddr).
					Str("tls_version", ri.TLSVersion.String()).
					Str("username", ai.Username).
					Str("remote_ip", ri.RemoteIP).
					Str("remote_country", ri.GeoipInfo.Country).
					Str("remote_region", ri.GeoipInfo.Region).
					Str("remote_city", ri.GeoipInfo.City).
					Str("http_method", req.Method).
					Str("http_host", host).
					Str("http_domain", domain).
					Str("http_proto", req.Proto).
					Str("user_agent", req.UserAgent()).
					Str("user_agent_os", ri.UserAgent.OS).
					Str("user_agent_os_version", ri.UserAgent.OSVersion).
					Str("user_agent_name", ri.UserAgent.Name).
					Str("user_agent_version", ri.UserAgent.Version).
					Value(),
				FieldName: "transmit_bytes",
				Interval:  cmp.Or(h.Config.Forward.LogInterval, 1),
			}
		}

		transmitBytes, err = io.CopyBuffer(w, NewRateLimitReader(resp.Body, ai.SpeedLimit), make([]byte, 1024*1024)) // buffer size should align to http2.MaxReadFrameSize
		log.Debug().Context(ri.LogContext).Str("username", ai.Username).Str("http_domain", domain).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
	}
}

type ForwardAuthInfo struct {
	Username   string `csv:"username"`
	Password   string `csv:"password"`
	SpeedLimit int64  `csv:"speedlimit"`
	VIP        int    `csv:"vip"`
}

func (h *HTTPForwardHandler) GetAuthInfo(ri *RequestInfo, req *http.Request) (ForwardAuthInfo, error) {
	authorization := req.Header.Get("proxy-authorization")
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 1 {
		return ForwardAuthInfo{}, fmt.Errorf("invaild auth header: %s", authorization)
	}
	if parts[0] != "Basic" {
		return ForwardAuthInfo{}, fmt.Errorf("unsupported auth header: %s", authorization)
	}

	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ForwardAuthInfo{}, err
	}

	parts = strings.SplitN(string(data), ":", 2)
	if len(parts) == 1 {
		return ForwardAuthInfo{}, fmt.Errorf("invaild auth header: %s", authorization)
	}

	username, password := parts[0], parts[1]

	var ai ForwardAuthInfo

	records := h.csvloader.Load()
	if records == nil {
		return ai, fmt.Errorf("empty records in csvloader %s", h.csvloader.Filename)
	}
	if i := slices.IndexFunc(*records, func(r ForwardAuthInfo) bool {
		if r.Username != username {
			return false
		}
		switch {
		case strings.HasPrefix(r.Password, "$2a$"):
			return bcrypt.CompareHashAndPassword([]byte(r.Password), []byte(password)) == nil
		default:
			return r.Password == password
		}
	}); i >= 0 {
		ai = (*records)[i]
	}
	if ai.Username == "" {
		return ai, fmt.Errorf("wrong username='%s' or password='%s'", username, password)
	}

	return ai, nil
}

func RejectRequest(rw http.ResponseWriter, req *http.Request) {
	time.Sleep(time.Duration(1+fastrandn(3)) * time.Second)
	// http.Error(rw, "403 Forbidden", http.StatusForbidden)
	http.Error(rw, "400 Bad Request", http.StatusBadRequest)
}

type ForwardLogWriter struct {
	io.Writer
	Logger    log.Logger
	Context   log.Context
	FieldName string
	Interval  int64

	timestamp int64
	transmits int64
}

func (w *ForwardLogWriter) Write(buf []byte) (n int, err error) {
	n, err = w.Writer.Write(buf)
	now := time.Now().Unix()
	if w.transmits != 0 && (w.timestamp == 0 || now-w.timestamp >= w.Interval || err != nil) {
		w.Logger.Log().Context(w.Context).Int64(w.FieldName, w.transmits).Msg("forward log")
		w.timestamp = now
		w.transmits = 0
	} else {
		w.transmits += int64(n)
	}
	return
}
