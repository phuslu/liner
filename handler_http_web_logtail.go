package main

import (
	"bytes"
	"cmp"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/phuslu/log"
)

type HTTPWebLogtailHandler struct {
	Location       string
	AuthTable      string
	AuthUserLoader AuthUserLoader
	Broadcaster    *LogBroadcaster
}

func (h *HTTPWebLogtailHandler) Load() error {
	if h.AuthTable != "" {
		h.AuthUserLoader = NewAuthUserLoaderFromTable(h.AuthTable)
	}
	return nil
}

func (h *HTTPWebLogtailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.AuthUserLoader != nil {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user := &AuthUserInfo{
			Username: username,
			Password: password,
		}

		checker := &AuthUserLoadChecker{AuthUserLoader: h.AuthUserLoader}
		if err := checker.CheckAuthUser(r.Context(), user); err != nil {
			time.Sleep(100 * time.Millisecond) // mitigate brute force
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if user.Attrs["allow_log"] != "1" && user.Attrs["allow_log"] != "true" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	h.Broadcaster.ServeHTTP(w, r)
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

type LogBroadcaster struct {
	GlobalLevel string
	mu          sync.RWMutex
	clients     map[chan []byte]log.Level
}

func (b *LogBroadcaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}
	level := log.ParseLevel(cmp.Or(r.URL.Query().Get("level"), b.GlobalLevel))

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientChan := make(chan []byte, 1024)
	b.mu.Lock()
	if b.clients == nil {
		b.clients = make(map[chan []byte]log.Level)
	}
	b.clients[clientChan] = level
	clientCount := len(b.clients)
	b.mu.Unlock()

	log.Info().Str("remote_addr", r.RemoteAddr).Str("level", level.String()).Int("client_count", clientCount).Msg("log sse client connected")

	defer func() {
		b.mu.Lock()
		delete(b.clients, clientChan)
		close(clientChan)
		clientCount := len(b.clients)
		b.mu.Unlock()

		log.Info().Str("remote_addr", r.RemoteAddr).Int("client_count", clientCount).Msg("log sse client disconnected")
	}()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case data := <-clientChan:
			// 处理多行日志，确保 SSE 格式正确
			lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
			for _, line := range lines {
				if len(line) > 0 {
					fmt.Fprintf(w, "data: %s\n", line)
				}
			}
			fmt.Fprint(w, "\n")
			flusher.Flush()
		}
	}
}

func (b *LogBroadcaster) WriteEntry(e *log.Entry) (int, error) {
	b.mu.RLock()
	if len(b.clients) == 0 {
		b.mu.RUnlock()
		return 0, nil
	}
	b.mu.RUnlock()

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	w := log.IOWriter{Writer: buf}
	w.WriteEntry(e)
	data := bytes.Clone(buf.Bytes())

	b.mu.RLock()
	for client, level := range b.clients {
		if e.Level >= level {
			select {
			case client <- data:
			default:
			}
		}
	}
	b.mu.RUnlock()
	return 0, nil
}

func (b *LogBroadcaster) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for client := range b.clients {
		close(client)
	}
	b.clients = nil
	return nil
}
