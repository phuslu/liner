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
	AuthTable       string
	AuthBasic       string
	MemoryLogWriter *ringbuffer.RingBuffer

	userchecker AuthUserChecker
	clients     *xsync.Map[*http.Request, http.ResponseWriter]
}

func (h *HTTPWebLogtailHandler) Load() error {
	if table := h.AuthTable; table != "" {
		loader := NewAuthUserLoaderFromTable(table)
		records, err := loader.LoadAuthUsers(context.Background())
		if err != nil {
			log.Fatal().Err(err).Str("auth_table", table).Msg("load auth_table failed")
		}
		log.Info().Str("auth_table", table).Int("auth_table_size", len(records)).Msg("load auth_table ok")
		h.userchecker = &AuthUserLoadChecker{loader}
	}

	h.clients = xsync.NewMap[*http.Request, http.ResponseWriter]()
	go h.broadcast()

	return nil
}

func (h *HTTPWebLogtailHandler) broadcast() {
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
}

func (h *HTTPWebLogtailHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	log.Info().Context(ri.LogContext).Any("headers", req.Header).Msg("web logtail request")

	if h.userchecker != nil {
		err := h.userchecker.CheckAuthUser(req.Context(), &ri.AuthUserInfo)
		if err == nil {
			if allow := ri.AuthUserInfo.Attrs["allow_logtail"]; allow != "1" {
				err = fmt.Errorf("logtail is not allow for user: %#v", ri.AuthUserInfo.Username)
			}
		}
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Any("user_attrs", ri.AuthUserInfo.Attrs).Msg("web logtail auth error")
			rw.Header().Set("www-authenticate", `Basic realm="`+h.AuthBasic+`"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)

			return
		}
	}

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
