package main

import (
	"errors"
	"net/http"

	"github.com/phuslu/fastcgi"
	"github.com/phuslu/log"
)

type HTTPWebFastcgiHandler struct {
	Location string
	Root     string

	fcgi *fastcgi.Handler
}

func (h *HTTPWebFastcgiHandler) Load() (err error) {
	root := h.Root
	if root == "" {
		return errors.New("empty cgi root")
	}

	h.fcgi = &fastcgi.Handler{
		Root:   h.Root,
		Logger: log.DefaultLogger.Slog(),
	}

	return
}

func (h *HTTPWebFastcgiHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)

	log.Info().Context(ri.LogContext).Msg("web fastcgi request")

	h.fcgi.ServeHTTP(rw, req)
}
