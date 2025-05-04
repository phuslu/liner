package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
)

type HTTPWebProxyHandler struct {
	Transport         *http.Transport
	Functions         template.FuncMap
	Pass              string
	AuthBasic         string
	AuthBasicUserFile string
	SetHeaders        string
	DumpFailure       bool

	proxypass *template.Template
	headers   *template.Template
}

func (h *HTTPWebProxyHandler) Load() error {
	var err error

	h.proxypass, err = template.New(h.Pass).Funcs(h.Functions).Parse(h.Pass)
	if err != nil {
		return err
	}

	h.headers, err = template.New(h.SetHeaders).Funcs(h.Functions).Parse(h.SetHeaders)
	if err != nil {
		return err
	}

	return nil
}

func (h *HTTPWebProxyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	// if req.Method == http.MethodConnect {
	// 	RejectRequest(rw, req)
	// 	return
	// }

	if h.AuthBasicUserFile != "" {
		if err := HtpasswdVerify(h.AuthBasicUserFile, req); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Error().Context(ri.LogContext).Err(err).Msg("web dav auth error")
			rw.Header().Set("www-authenticate", `Basic realm="`+h.AuthBasic+`"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)

			return
		}
	}

	var sb strings.Builder
	h.proxypass.Execute(&sb, struct {
		Request    *http.Request
		UserAgent  *useragent.UserAgent
		ServerAddr string
	}{req, &ri.UserAgent, ri.ServerAddr})

	proxypass := strings.TrimSpace(sb.String())
	if code, _ := strconv.Atoi(proxypass); 100 <= code && code <= 999 {
		http.Error(rw, fmt.Sprintf("%d %s", code, http.StatusText(code)), code)
		return
	}

	u, err := url.Parse(proxypass)
	if err != nil {
		http.Error(rw, fmt.Sprintf("bad proxypass %+v", proxypass), http.StatusServiceUnavailable)
		return
	}

	if u.Scheme == "file" {
		http.Error(rw, "use index_root instead of file://", http.StatusServiceUnavailable)
		return
	}

	if protocol := req.Header.Get(":protocol"); protocol != "" && req.ProtoMajor == 2 && req.Method == http.MethodConnect && req.RequestURI[0] == '/' {
		switch protocol {
		case "websocket":
			break
		default:
			http.Error(rw, "pesudo protocol "+protocol+" is not supportted", http.StatusBadGateway)
			return
		}
		hostport := u.Host
		if _, _, err := net.SplitHostPort(hostport); err != nil {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			hostport = net.JoinHostPort(hostport, port)
		}

		// conn, err := net.DialTimeout("tcp", hostport, time.Duration(cmp.Or(h.DialTimeout, 5))*time.Second)
		conn, err := h.Transport.DialContext(req.Context(), "tcp", hostport)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("proxypass", proxypass).Str("hostport", hostport).Msg("http2 connect proxypass error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		defer conn.Close()

		if u.Scheme == "https" {
			tlsConn := tls.Client(conn, h.Transport.TLSClientConfig)
			err := tlsConn.HandshakeContext(req.Context())
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			conn = tlsConn
		}

		b := make([]byte, 0, 1024)
		b = fmt.Appendf(b, "GET %s HTTP/1.1\r\n", req.RequestURI)
		for key, values := range req.Header {
			for _, value := range values {
				if strings.HasPrefix(key, ":") {
					continue
				}
				b = fmt.Appendf(b, "%s: %s\n", key, value)
			}
		}
		wskey := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%x%x\n", fastrandn(1<<32-1), fastrandn(1<<32-1))))
		b = fmt.Appendf(b, "Sec-WebSocket-Key: %s\r\n", wskey)
		b = fmt.Appendf(b, "Connection: Upgrade\r\n")
		b = fmt.Appendf(b, "Upgrade: %s\r\n", req.Header.Get(":protocol"))
		b = fmt.Appendf(b, "Host: %s\r\n", req.Host)
		b = fmt.Appendf(b, "\r\n")

		_, err = conn.Write(b)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("proxypass", proxypass).Str("hostport", hostport).Msg("http2 write to proxypass error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("proxypass", proxypass).Str("hostport", hostport).Msg("http2 read from proxypass error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		log.Info().Context(ri.LogContext).Str("proxypass", proxypass).Str("hostport", hostport).Int("resp_statuscode", resp.StatusCode).Interface("resp_header", resp.Header).Msg("http2 get response ok")

		if resp.StatusCode != http.StatusSwitchingProtocols {
			log.Error().Context(ri.LogContext).Err(err).Str("proxypass", proxypass).Str("hostport", hostport).Int("resp_statuscode", resp.StatusCode).Msg("http2 swtich 101 from proxypass error")
			http.Error(rw, "switch protocols failed, resp statuscode: "+strconv.Itoa(resp.StatusCode), http.StatusBadGateway)
			return
		}

		for key, values := range resp.Header {
			for _, value := range values {
				rw.Header().Add(key, value)
			}
		}
		rw.WriteHeader(http.StatusOK)

		rwc := HTTP2ReadWriteCloser{req.Body, rw}
		defer rwc.Close()

		go io.Copy(rwc, br)
		io.Copy(conn, rwc)

		return
	}

	var tr http.RoundTripper = h.Transport

	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	// req.Host = u.Host

	if s := req.Header.Get("x-forwarded-for"); s != "" {
		req.Header.Set("x-forwarded-for", s+", "+ri.RemoteIP)
	} else {
		req.Header.Set("x-forwarded-for", ri.RemoteIP)
	}

	if ip, err := netip.ParseAddr(ri.RemoteIP); err == nil && !ip.IsLoopback() && !ip.IsPrivate() {
		req.Header.Set("x-real-ip", ri.RemoteIP)
	}

	if ri.TLSVersion != 0 {
		req.Header.Set("x-forwarded-proto", "https")
		// req.Header.Set("x-forwarded-ssl", "on")
		// req.Header.Set("x-url-scheme", "https")
		// req.Header.Set("x-http-proto", req.Proto)
		req.Header.Set("x-ja3-fingerprint", getTlsFingerprint(ri.TLSVersion, ri.ClientHelloInfo, ri.ClientHelloRaw))
	}
	h.setHeaders(req, ri)

	if req.ProtoAtLeast(3, 0) && req.Method == http.MethodGet {
		req.Body, req.ContentLength = nil, 0
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		if h.proxypass != nil {
			log.Warn().Err(err).Context(ri.LogContext).Str("req_host", req.Host).Str("req_url", req.URL.String()).Msg("proxypass error")
			if IsTimeout(err) {
				http.Error(rw, "504 Gateway Timeout", http.StatusGatewayTimeout)
			} else {
				http.Error(rw, "502 Bad Gateway", http.StatusBadGateway)
			}
		} else {
			http.NotFound(rw, req)
		}
		return
	}

	log.Info().Context(ri.LogContext).Int("http_status", resp.StatusCode).Int64("http_content_length", resp.ContentLength).Msg("proxy_pass request")

	if req.ProtoAtLeast(2, 0) {
		resp.Header.Del("connection")
		resp.Header.Del("keep-alive")
	}

	if h.DumpFailure && resp.StatusCode >= http.StatusBadRequest {
		data, err := httputil.DumpResponse(resp, true)
		if err != nil {
			log.Warn().Err(err).Context(ri.LogContext).Int("status", resp.StatusCode).Int64("content_length", resp.ContentLength).Msg("DumpFailureResponse error")
		} else {
			log.Info().Context(ri.LogContext).Int("status", resp.StatusCode).Int64("content_length", resp.ContentLength).Str("data", string(data)).Msg("DumpFailureResponse ok")
		}
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		conn, ok := resp.Body.(io.ReadWriteCloser)
		if !ok {
			http.Error(rw, fmt.Sprintf("internal error: 101 switching protocols response with non-writable body"), 500)
			return
		}
		defer conn.Close()

		for k, vv := range resp.Header {
			for _, v := range vv {
				rw.Header().Add(k, v)
			}
		}
		rw.WriteHeader(resp.StatusCode)

		hijacker, ok := rw.(http.Hijacker)
		if !ok {
			http.Error(rw, fmt.Sprintf("%#v is not http.Hijacker", rw), http.StatusBadGateway)
			return
		}
		lconn, flusher, err := hijacker.Hijack()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		defer lconn.Close()
		if err := flusher.Flush(); err != nil {
			http.Error(rw, fmt.Sprintf("response flush: %v", err), 500)
			return
		}

		go io.Copy(lconn, conn)
		io.Copy(conn, lconn)
	} else {
		if location := resp.Header.Get("location"); location != "" {
			prefix := "http://" + req.Host + "/"
			if strings.HasPrefix(location, prefix) && ri.TLSVersion != 0 {
				resp.Header.Set("location", location[len(prefix)-1:])
			}
		}
		for key, values := range resp.Header {
			for _, value := range values {
				rw.Header().Add(key, value)
			}
		}
		rw.WriteHeader(resp.StatusCode)
		defer resp.Body.Close()
		io.Copy(rw, resp.Body)
	}
}

func (h *HTTPWebProxyHandler) setHeaders(req *http.Request, ri *RequestInfo) {
	if h.SetHeaders == "" {
		return
	}

	var sb strings.Builder
	h.headers.Execute(&sb, struct {
		Request    *http.Request
		UserAgent  *useragent.UserAgent
		ServerAddr string
	}{req, &ri.UserAgent, ri.ServerAddr})

	for _, line := range strings.Split(sb.String(), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], strings.TrimSpace(parts[1])
		switch key {
		case "host", "Host", "HOST":
			req.URL.Host = value
			req.Host = value
		default:
			req.Header.Set(key, value)
		}
	}
}

func getTlsFingerprint(version TLSVersion, info *tls.ClientHelloInfo, raw []byte) string {
	var sb strings.Builder

	// version
	fmt.Fprintf(&sb, "%d,", version)

	// ciphers
	i := 0
	for _, c := range info.CipherSuites {
		if IsTLSGreaseCode(c) {
			continue
		}
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(&sb, "%d", c)
		i++
	}
	sb.WriteByte(',')

	i = 0
	for _, c := range info.Extensions {
		if IsTLSGreaseCode(c) || c == 0x0015 {
			continue
		}
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(&sb, "%d", c)
		i++
	}
	sb.WriteByte(',')

	// groups
	i = 0
	for _, c := range info.SupportedCurves {
		if IsTLSGreaseCode(uint16(c)) {
			continue
		}
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(&sb, "%d", c)
		i++
	}
	sb.WriteByte(',')

	// formats
	for i, c := range info.SupportedPoints {
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(&sb, "%d", c)
	}

	return sb.String()
}
