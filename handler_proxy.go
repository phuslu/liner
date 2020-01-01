package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strings"

	"github.com/phuslu/log"
)

const (
	DefaultProxyPass = "http://127.0.0.1:80"
)

type ProxyHandler struct {
	Config    HTTPConfig
	Transport *http.Transport

	Upstream *url.URL
}

func (h *ProxyHandler) Load() error {
	var err error

	var u = h.Config.ProxyPass
	if u == "" {
		u = DefaultProxyPass
	}

	h.Upstream, err = url.Parse(u)
	if err != nil {
		return err
	}

	return nil
}

func (h *ProxyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(RequestInfo)

	// if req.Method == http.MethodConnect {
	// 	RejectRequest(rw, req)
	// 	return
	// }

	upstream := h.Upstream
	if upstream == nil {
		upstream = &url.URL{
			Scheme: "http",
			Host:   "127.0.0.1:80",
		}
	}

	if upstream.Scheme == "file" {
		var path string
		switch runtime.GOOS {
		case "windows":
			path = strings.TrimLeft(upstream.Path, "/")
		default:
			path = upstream.Path
		}
		http.FileServer(http.Dir(path)).ServeHTTP(rw, req)
		return
	}

	var tr http.RoundTripper = h.Transport

	req.URL.Scheme = upstream.Scheme
	req.URL.Host = upstream.Host

	if s := req.Header.Get("x-forwarded-for"); s != "" {
		req.Header.Set("x-forwarded-for", s+", "+ri.RemoteIP)
	} else {
		req.Header.Set("x-forwarded-for", ri.RemoteIP)
	}

	if !IsReservedIP(net.ParseIP(ri.RemoteIP)) {
		req.Header.Set("x-real-ip", ri.RemoteIP)
	}

	if ri.TLSVersion != 0 {
		req.Header.Set("x-forwarded-proto", "https")
		req.Header.Set("x-tls-version", ri.TLSVersion.String())
	}

	for key, value := range h.Config.ProxySetHeaders {
		switch strings.ToLower(key) {
		case "host":
			req.URL.Host = value
			req.Host = value
		default:
			req.Header.Set(key, value)
		}
	}

	if req.ProtoAtLeast(3, 0) && req.Method == http.MethodGet {
		req.Body = nil
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		if h.Upstream != nil {
			log.Warn().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Err(err).Msg("upstream error")
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

	log.Info().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Int("http_status", resp.StatusCode).Int64("http_content_length", resp.ContentLength).Str("user_agent", req.UserAgent()).Msg("proxy_pass request")

	if req.ProtoAtLeast(2, 0) {
		resp.Header.Del("connection")
		resp.Header.Del("keep-alive")
	}

	if req.ProtoMajor == 2 && req.TLS != nil && req.TLS.Version == tls.VersionTLS13 {
		_, port, _ := net.SplitHostPort(ri.ServerAddr)
		resp.Header.Add("Alt-Svc", fmt.Sprintf(`%s=":%s"; ma=86400`, nextProtoH3, port))
	}

	if h.Config.ProxyDumpFailure && resp.StatusCode >= http.StatusBadRequest {
		data, err := httputil.DumpResponse(resp, true)
		if err != nil {
			log.Warn().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Int("status", resp.StatusCode).Int64("content_length", resp.ContentLength).Str("user_agent", req.UserAgent()).Err(err).Msg("DumpFailureResponse error")
		} else {
			log.Info().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Int("status", resp.StatusCode).Int64("content_length", resp.ContentLength).Str("user_agent", req.UserAgent()).Str("data", string(data)).Msg("DumpFailureResponse ok")
		}
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		var w io.Writer
		var r io.Reader

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

		if req.ProtoAtLeast(2, 0) {
			flusher, ok := rw.(http.Flusher)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Flusher", rw), http.StatusBadGateway)
				return
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

			w = lconn
			r = lconn
		}

		go io.Copy(w, conn)
		io.Copy(conn, r)
	} else {
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
