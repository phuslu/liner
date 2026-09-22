package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/phuslu/log"
)

type HTTPWebCgiHandler struct {
	Location string
	Root     string
	Timeout  int

	MaxConcurrency int

	prefix string
	root   string
	sem    chan struct{}
}

func (h *HTTPWebCgiHandler) Load(_ context.Context) error {
	fullname, err := filepath.Abs(h.Root)
	if err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(fullname)
	if err != nil {
		return fmt.Errorf("cgi root %q is unusable: %w", h.Root, err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("cgi root %q is unusable: %w", h.Root, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("cgi root %q is not a directory", h.Root)
	}
	h.root = root
	h.prefix = strings.TrimSuffix(h.Location, "/") + "/"
	if h.MaxConcurrency > 0 {
		h.sem = make(chan struct{}, h.MaxConcurrency)
	}
	return nil
}

// locate resolves the request path into an executable script, its SCRIPT_NAME and
// the trailing PATH_INFO. It rejects path traversal and any script that resolves
// outside the configured root through a symlink.
func (h *HTTPWebCgiHandler) locate(req *http.Request) (scriptPath, scriptName, pathInfo string, ok bool) {
	if !strings.HasPrefix(req.URL.Path, h.prefix) {
		return
	}
	segments := strings.Split(strings.TrimPrefix(req.URL.Path, h.prefix), "/")

	cur := ""
	for i, segment := range segments {
		switch segment {
		case "", ".":
			continue
		case "..":
			return
		}
		cur += "/" + segment
		fullname := filepath.Join(h.root, filepath.FromSlash(cur))
		fi, err := os.Stat(fullname)
		if err != nil || !fi.Mode().IsRegular() || !strings.EqualFold(filepath.Ext(fullname), ".cgi") {
			continue
		}
		real, err := filepath.EvalSymlinks(fullname)
		if err != nil || !strings.HasPrefix(real, h.root+string(filepath.Separator)) {
			return
		}
		rest := segments[i+1:]
		if len(rest) > 0 {
			pathInfo = "/" + strings.Join(rest, "/")
		}
		return real, h.prefix + strings.TrimPrefix(cur, "/"), pathInfo, true
	}
	return
}

func (h *HTTPWebCgiHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)

	log.Debug().Context(ri.LogContext).Object("headers", HTTPHeaderMarshalLogObject(req.Header)).Msg("web cgi request")

	scriptPath, scriptName, pathInfo, ok := h.locate(req)
	if !ok {
		http.NotFound(rw, req)
		return
	}

	if h.sem != nil {
		select {
		case h.sem <- struct{}{}:
			defer func() { <-h.sem }()
		case <-req.Context().Done():
			http.Error(rw, "504 gateway timeout", http.StatusGatewayTimeout)
			return
		}
	}

	ctx := req.Context()
	if h.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Timeout)*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, scriptPath)
	cmd.Dir = filepath.Dir(scriptPath)
	cmd.Env = h.environ(req, ri, scriptPath, scriptName, pathInfo)
	cmd.Stdin = req.Body

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Msg("web cgi stdout pipe error")
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	stderr := &cgiStderrWriter{max: 4096}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		log.Error().Context(ri.LogContext).Err(err).Str("cgi_script", scriptName).Msg("web cgi start error")
		http.Error(rw, "502 bad gateway", http.StatusBadGateway)
		return
	}

	reader := bufio.NewReader(stdout)
	status, header, err := cgiReadResponseHeader(reader)
	if err != nil {
		_ = cmd.Wait()
		if ctx.Err() != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("cgi_script", scriptName).Msg("web cgi timeout")
			http.Error(rw, "504 gateway timeout", http.StatusGatewayTimeout)
			return
		}
		log.Error().Context(ri.LogContext).Err(err).Str("cgi_script", scriptName).Str("cgi_stderr", stderr.String()).Msg("web cgi invalid response headers")
		http.Error(rw, "502 bad gateway", http.StatusBadGateway)
		return
	}

	dst := rw.Header()
	for key, values := range header {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	rw.WriteHeader(status)

	n, copyErr := io.Copy(rw, reader)
	waitErr := cmd.Wait()

	err = copyErr
	if err == nil {
		err = waitErr
	}
	logger := log.Info()
	if err != nil {
		logger = log.Error()
	}
	logger.Context(ri.LogContext).Err(err).Str("cgi_script", scriptName).Int("http_status", status).Int64("http_content_length", n).Str("cgi_stderr", stderr.String()).Msg("web cgi request")
}

func (h *HTTPWebCgiHandler) environ(req *http.Request, ri *HTTPRequestInfo, scriptPath, scriptName, pathInfo string) []string {
	hostname, port := req.Host, ""
	if name, p, err := net.SplitHostPort(req.Host); err == nil {
		hostname, port = name, p
	}
	if port == "" {
		if req.TLS != nil {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Minimal environment only, the server process environment is intentionally not inherited.
	env := make([]string, 0, 32+len(req.Header))
	env = append(env,
		"PATH="+cmp.Or(os.Getenv("PATH"), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
		"GATEWAY_INTERFACE=CGI/1.1",
		"SERVER_SOFTWARE=liner/"+version,
		"SERVER_PROTOCOL="+cmp.Or(req.Proto, "HTTP/1.1"),
		"SERVER_NAME="+hostname,
		"SERVER_PORT="+port,
		"SERVER_ADDR="+ri.ServerAddr.Addr().String(),
		"REQUEST_METHOD="+req.Method,
		"REQUEST_URI="+req.RequestURI,
		"QUERY_STRING="+req.URL.RawQuery,
		"SCRIPT_NAME="+scriptName,
		"SCRIPT_FILENAME="+scriptPath,
		"DOCUMENT_ROOT="+h.root,
		"REMOTE_ADDR="+ri.RealIP.String(),
		"REMOTE_PORT="+strconv.Itoa(int(ri.RemoteAddr.Port())),
	)
	if pathInfo != "" {
		env = append(env,
			"PATH_INFO="+pathInfo,
			"PATH_TRANSLATED="+filepath.Join(h.root, filepath.FromSlash(pathInfo)),
		)
	}
	if contentType := req.Header.Get("Content-Type"); contentType != "" {
		env = append(env, "CONTENT_TYPE="+contentType)
	}
	if req.ContentLength >= 0 {
		env = append(env, "CONTENT_LENGTH="+strconv.FormatInt(req.ContentLength, 10))
	}
	if req.TLS != nil {
		env = append(env, "HTTPS=on")
	}
	if ri.AuthUserInfo.Username != "" {
		env = append(env, "REMOTE_USER="+ri.AuthUserInfo.Username, "AUTH_TYPE=Basic")
	}
	for key, values := range req.Header {
		switch key {
		case "Content-Type", "Content-Length":
			continue
		// drop the Proxy header to avoid the httpoxy CGI vulnerability (HTTP_PROXY).
		case "Proxy":
			continue
		}
		env = append(env, "HTTP_"+strings.ToUpper(strings.ReplaceAll(key, "-", "_"))+"="+strings.Join(values, ", "))
	}
	return env
}

// cgiReadResponseHeader parses a CGI response header block and returns the status
// code, the response headers and a reader positioned at the response body.
func cgiReadResponseHeader(reader *bufio.Reader) (int, textproto.MIMEHeader, error) {
	header, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil && len(header) == 0 {
		if err == io.EOF {
			return http.StatusOK, nil, nil
		}
		return 0, nil, err
	}

	status := http.StatusOK
	if s := strings.TrimSpace(header.Get("Status")); s != "" {
		header.Del("Status")
		if code, _, _ := strings.Cut(s, " "); code != "" {
			if n, err := strconv.Atoi(code); err == nil && n >= 100 && n <= 599 {
				status = n
			}
		}
	} else if header.Get("Location") != "" {
		status = http.StatusFound
	}
	return status, header, nil
}

// cgiStderrWriter buffers child stderr up to max bytes and silently discards the
// rest, so a chatty script can never block on a full pipe.
type cgiStderrWriter struct {
	buf bytes.Buffer
	max int
}

func (w *cgiStderrWriter) Write(p []byte) (int, error) {
	if n := w.max - w.buf.Len(); n > 0 {
		if len(p) > n {
			w.buf.Write(p[:n])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

func (w *cgiStderrWriter) String() string {
	return w.buf.String()
}
