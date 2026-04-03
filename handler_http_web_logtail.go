package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/phuslu/log"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/smallnest/ringbuffer"
)

type HTTPWebLogtailHandler struct {
	Location        string
	MemoryLogWriter *ringbuffer.RingBuffer

	clients *xsync.Map[*http.Request, http.ResponseWriter]
}

func (h *HTTPWebLogtailHandler) Load(ctx context.Context) error {
	h.clients = xsync.NewMap[*http.Request, http.ResponseWriter]()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := h.MemoryLogWriter.Read(buf)
			if n == 0 {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			if err != nil {
				log.Error().Err(err).Msg("logtail read ringbuffer error")
				return
			}
			buf = buf[:n]
			h.clients.Range(func(req *http.Request, rw http.ResponseWriter) bool {
				// level := log.ParseLevel(cmp.Or(req.URL.Query().Get("level"), "info"))
				fmt.Fprint(rw, string(buf))
				http.NewResponseController(rw).Flush()
				return true
			})
		}
	}()

	return nil
}

func (h *HTTPWebLogtailHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	log.Info().Context(ri.LogContext).Any("headers", req.Header).Msg("web logtail request")

	_, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("Access-Control-Allow-Origin", "*")

	h.clients.Store(req, rw)
	<-req.Context().Done()
	h.clients.Delete(req)
}
