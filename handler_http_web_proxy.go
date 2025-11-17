package main

import (
	"bufio"
	"context"
	"crypto/tls"
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
	"github.com/quic-go/quic-go/http3"
	"github.com/valyala/bytebufferpool"
)

type HTTPWebProxyHandler struct {
	Transport   *http.Transport
	Functions   template.FuncMap
	Pass        string
	AuthBasic   string
	AuthTable   string
	StripPrefix string
	SetHeaders  string
	DumpFailure bool

	userchecker AuthUserChecker
	proxypass   struct {
		Code     int
		URL      *url.URL
		Template *template.Template
	}
	h3transport *http3.Transport
	headers     *template.Template
}

func (h *HTTPWebProxyHandler) Load() error {
	var err error

	if table := h.AuthTable; table != "" {
		loader := NewAuthUserLoaderFromTable(table)
		records, err := loader.LoadAuthUsers(context.Background())
		if err != nil {
			log.Fatal().Err(err).Str("proxy_pass", h.Pass).Str("auth_table", table).Msg("load auth_table failed")
		}
		log.Info().Str("proxy_pass", h.Pass).Str("auth_table", table).Int("auth_table_size", len(records)).Msg("load auth_table ok")
		h.userchecker = &AuthUserLoadChecker{loader}
	}

	if code, err := strconv.Atoi(strings.TrimSpace(h.Pass)); err == nil && code > 0 {
		h.proxypass.Code = code
	} else if !strings.Contains(h.Pass, "{{") {
		h.proxypass.URL, err = url.Parse(strings.TrimSpace(h.Pass))
		if err != nil {
			return err
		}
	} else {
		h.proxypass.Template, err = template.New(h.Pass).Funcs(h.Functions).Parse(h.Pass)
		if err != nil {
			return err
		}
	}

	h.h3transport = &http3.Transport{
		DisableCompression: false,
		EnableDatagrams:    true,
	}

	if strings.Contains(h.SetHeaders, "{{") {
		h.headers, err = template.New(h.SetHeaders).Funcs(h.Functions).Parse(h.SetHeaders)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *HTTPWebProxyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)

	// if req.Method == http.MethodConnect {
	// 	RejectRequest(rw, req)
	// 	return
	// }

	if h.userchecker != nil {
		err := h.userchecker.CheckAuthUser(req.Context(), &ri.AuthUserInfo)
		if err == nil {
			if allow := ri.AuthUserInfo.Attrs["allow_proxy"]; allow != "1" {
				err = fmt.Errorf("webdav is not allow for user: %#v", ri.AuthUserInfo.Username)
			}
		}
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Any("user_attrs", ri.AuthUserInfo.Attrs).Msg("web proxy auth error")
			rw.Header().Set("www-authenticate", `Basic realm="`+h.AuthBasic+`"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)

			return
		}
	}

	var proxypass *url.URL
	switch {
	case h.proxypass.Code > 0:
		http.Error(rw, fmt.Sprintf("%d %s", h.proxypass.Code, http.StatusText(h.proxypass.Code)), h.proxypass.Code)
		return
	case h.proxypass.URL != nil:
		proxypass = h.proxypass.URL
	default:
		ri.PolicyBuffer.Reset()
		h.proxypass.Template.Execute(&ri.PolicyBuffer, struct {
			Request         *http.Request
			RealIP          netip.Addr
			ClientHelloInfo *tls.ClientHelloInfo
			JA4             string
			UserAgent       *useragent.UserAgent
			ServerAddr      netip.AddrPort
		}{req, ri.RealIP, ri.ClientHelloInfo, ri.JA4, &ri.UserAgent, ri.ServerAddr})
		var err error
		proxypass, err = url.Parse(strings.TrimSpace(b2s(ri.PolicyBuffer.B)))
		if err != nil {
			http.Error(rw, fmt.Sprintf("bad proxypass %+v", proxypass), http.StatusServiceUnavailable)
			return
		}
	}

	if proxypass.Scheme == "file" {
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
		hostport := proxypass.Host
		if _, _, err := net.SplitHostPort(hostport); err != nil {
			port := "80"
			if proxypass.Scheme == "https" {
				port = "443"
			}
			hostport = net.JoinHostPort(hostport, port)
		}

		// conn, err := net.DialTimeout("tcp", hostport, time.Duration(cmp.Or(h.DialTimeout, 5))*time.Second)
		conn, err := h.Transport.DialContext(req.Context(), "tcp", hostport)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("proxypass", proxypass.String()).Str("hostport", hostport).Msg("http2 connect proxypass error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		defer conn.Close()

		if proxypass.Scheme == "https" {
			tlsConn := tls.Client(conn, h.Transport.TLSClientConfig)
			err := tlsConn.HandshakeContext(req.Context())
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			conn = tlsConn
		}

		wskey := AppendableBytes(make([]byte, 0, 128)).Uint64(uint64(fastrandn(1<<32-1)), 16).Uint64(uint64(fastrandn(1<<32-1)), 16)

		b := AppendableBytes(make([]byte, 0, 1024))
		b = b.Str("GET ").Str(req.RequestURI).Str(" HTTP/1.1\r\n")
		for key, values := range req.Header {
			for _, value := range values {
				if strings.HasPrefix(key, ":") {
					continue
				}
				b = b.Str(key).Str(": ").Str(value).Str("\r\n")
			}
		}
		b = b.Str("Sec-WebSocket-Key: ").Base64(wskey).Str("\r\n")
		b = b.Str("Upgrade: ").Str(req.Header.Get(":protocol")).Str("\r\n")
		b = b.Str("Host: ").Str(req.Host).Str("\r\n")
		b = b.Str("Connection: Upgrade\r\n")
		b = b.Str("\r\n")

		_, err = conn.Write(b)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("proxypass", proxypass.String()).Str("hostport", hostport).Msg("http2 write to proxypass error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("proxypass", proxypass.String()).Str("hostport", hostport).Msg("http2 read from proxypass error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		log.Info().Context(ri.LogContext).Str("proxypass", proxypass.String()).Str("hostport", hostport).Int("resp_statuscode", resp.StatusCode).Object("resp_header", HTTPHeaderMarshalLogObject(resp.Header)).Msg("http2 get response ok")

		if resp.StatusCode != http.StatusSwitchingProtocols {
			log.Error().Context(ri.LogContext).Err(err).Str("proxypass", proxypass.String()).Str("hostport", hostport).Int("resp_statuscode", resp.StatusCode).Msg("http2 swtich 101 from proxypass error")
			http.Error(rw, "switch protocols failed, resp statuscode: "+strconv.Itoa(resp.StatusCode), http.StatusBadGateway)
			return
		}

		for key, values := range resp.Header {
			for _, value := range values {
				rw.Header().Add(key, value)
			}
		}
		rw.WriteHeader(http.StatusOK)

		rwc := HTTPRequestStream{req.Body, rw, http.NewResponseController(rw), net.TCPAddrFromAddrPort(ri.RemoteAddr), net.TCPAddrFromAddrPort(ri.ServerAddr)}
		defer rwc.Close()

		go io.Copy(rwc, br)
		io.Copy(conn, rwc)

		return
	}

	var tr http.RoundTripper
	switch proxypass.Scheme {
	case "http3":
		tr = h.h3transport
		req.URL.Scheme = "https"
		req.URL.Host = proxypass.Host
		req.Host = proxypass.Host
	default:
		tr = h.Transport
		req.URL.Scheme = proxypass.Scheme
		req.URL.Host = proxypass.Host
		req.Host = proxypass.Host
	}

	if prefix := h.StripPrefix; prefix != "" {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
		req.RequestURI = strings.TrimPrefix(req.RequestURI, prefix)
	}

	if s := req.Header.Get("x-forwarded-for"); s != "" {
		req.Header.Set("x-forwarded-for", s+", "+ri.RemoteAddr.Addr().String())
	} else {
		req.Header.Set("x-forwarded-for", ri.RemoteAddr.Addr().String())
	}
	req.Header.Set("x-real-ip", ri.RealIP.String())

	if ri.TLSVersion != 0 {
		req.Header.Set("x-forwarded-proto", "https")
		// req.Header.Set("x-forwarded-ssl", "on")
		// req.Header.Set("x-url-scheme", "https")
		// req.Header.Set("x-http-proto", req.Proto)
		// req.Header.Set("x-ja4", string(ri.JA4))
	}

	if h.SetHeaders != "" {
		h.setHeaders(req, ri)
	}

	if req.ProtoAtLeast(3, 0) && req.Method == http.MethodGet {
		req.Body, req.ContentLength = nil, 0
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		log.Warn().Err(err).Context(ri.LogContext).Str("req_host", req.Host).Str("req_url", req.URL.String()).Msg("proxypass error")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || os.IsTimeout(err) {
			http.Error(rw, "504 Gateway Timeout", http.StatusGatewayTimeout)
		} else {
			http.Error(rw, "502 Bad Gateway", http.StatusBadGateway)
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

		lconn, flusher, err := http.NewResponseController(rw).Hijack()
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

func (h *HTTPWebProxyHandler) setHeaders(req *http.Request, ri *HTTPRequestInfo) {
	var headers string
	if h.headers != nil {
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		bb.Reset()
		h.headers.Execute(bb, struct {
			Request         *http.Request
			RealIP          netip.Addr
			ClientHelloInfo *tls.ClientHelloInfo
			JA4             string
			UserAgent       *useragent.UserAgent
			ServerAddr      netip.AddrPort
		}{req, ri.RealIP, ri.ClientHelloInfo, ri.JA4, &ri.UserAgent, ri.ServerAddr})
		headers = bb.String()
	} else {
		headers = h.SetHeaders
	}

	for line := range strings.Lines(headers) {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], strings.TrimSpace(parts[1])
		switch key {
		case "host", "Host", "HOST":
			req.URL.Host = value
			req.Host = value
		}
		req.Header.Set(key, value)
	}
}
