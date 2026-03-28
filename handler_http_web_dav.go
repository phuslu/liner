package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/phuslu/log"
	"golang.org/x/net/webdav"
)

type HTTPWebDavHandler struct {
	Root string

	dav *webdav.Handler
}

func (h *HTTPWebDavHandler) Load(ctx context.Context) (err error) {
	root := h.Root
	if root == "" {
		root = "/"
	}

	h.dav = &webdav.Handler{
		FileSystem: webdav.Dir(root),
		LockSystem: webdav.NewMemLS(),
	}

	return
}

func (h *HTTPWebDavHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	log.Info().Context(ri.LogContext).Any("headers", req.Header).Msg("web dav request")

	if strings.Contains(req.RequestURI, "../") || strings.Contains(req.RequestURI, "/..") {
		http.Error(rw, "400 Bad Request: "+req.RequestURI, http.StatusBadRequest)
		return
	}

	h.dav.ServeHTTP(rw, req)
}
