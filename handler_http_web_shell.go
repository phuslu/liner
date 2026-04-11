package main

import (
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/coder/websocket"
	"github.com/creack/pty/v2"
	"github.com/phuslu/log"
)

type HTTPWebShellHandler struct {
	Location  string
	Command   string
	Home      string
	Template  map[string]string
	Functions *Functions

	webshell *template.Template
}

func (h *HTTPWebShellHandler) Load(ctx context.Context) error {
	webshell := webshellHtml
	if replacer, _ := ctx.Value(HTTPCDNJSReplacerContextKey).(*strings.Replacer); replacer != nil {
		webshell = replacer.Replace(webshell)
	}

	var err error

	h.webshell, err = h.Functions.ParseTemplate("http_web_shell_webshell", webshell)
	if err != nil {
		return err
	}

	return nil
}

func (h *HTTPWebShellHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	log.Info().Context(ri.LogContext).Any("headers", req.Header).Msg("web shell request")

	if strings.Contains(req.RequestURI, "..") {
		http.Error(rw, "400 Bad Request: "+req.RequestURI, http.StatusBadRequest)
		return
	}

	path := strings.TrimPrefix(req.URL.Path, h.Location)

	switch path {
	case "ws":
		break
	case "":
		var b bytes.Buffer
		var err error
		if obfuscated {
			err = h.webshell.Execute(&b, map[string]any{
				"Request":  req,
				"Template": h.Template,
			})
		} else {
			err = h.webshell.Execute(&b, struct {
				Request  *http.Request
				Template map[string]string
			}{
				Request:  req,
				Template: h.Template,
			})
		}
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		rw.Header().Set("content-type", "text/html; charset=utf-8")
		rw.Write(b.Bytes())
		return
	default:
		http.NotFound(rw, req)
		return
	}

	if u, err := url.Parse(req.Header.Get("origin")); err != nil || u.Host != req.Host {
		http.Error(rw, "404 forbidden: bad origin: "+req.Header.Get("origin"), http.StatusBadRequest)
		return
	}

	conn, err := websocket.Accept(rw, req, nil)
	if err != nil {
		http.Error(rw, "failed to accept websocket: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.CloseNow()

	ctx := req.Context()

	cmd := exec.CommandContext(ctx, cmp.Or(h.Command, "/bin/sh"))
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	cmd.Dir = cmp.Or(h.Home, os.Getenv("HOME"))

	ptyfile, err := pty.Start(cmd)
	if err != nil {
		conn.Close(websocket.StatusInternalError, "failed to start pty")
		return
	}
	defer func() {
		log.Info().Err(err).Msg("pty closed")
		_ = ptyfile.Close()
		_ = cmd.Process.Kill()
	}()

	go func() {
		err := cmd.Wait()
		log.Info().Err(err).Msg("child exited")
		_ = conn.Close(websocket.StatusNormalClosure, "child exited")
	}()

	go func(ctx context.Context) {
		buf := make([]byte, 4096)
		for {
			n, err := ptyfile.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Info().Err(err).Msg("pty read error")
				}
				_ = conn.Close(websocket.StatusNormalClosure, "pty session closed")
				return
			}
			err = conn.Write(ctx, websocket.MessageBinary, buf[:n])
			if err != nil {
				return
			}
		}
	}(ctx)

	for {
		typ, reader, err := conn.Reader(ctx)
		if err != nil {
			log.Printf("ws read error: %v", err)
			return
		}

		if typ == websocket.MessageBinary {
			if _, err := io.Copy(ptyfile, reader); err != nil {
				log.Printf("failed to write to pty: %v", err)
				return
			}
		} else if typ == websocket.MessageText {
			var msg struct {
				Type string `json:"type"`
				Rows int    `json:"rows"`
				Cols int    `json:"cols"`
			}
			if err := json.NewDecoder(reader).Decode(&msg); err != nil {
				log.Printf("invalid json: %v", err)
				continue
			}
			switch msg.Type {
			case "resize":
				ws := &pty.Winsize{Rows: uint16(msg.Rows), Cols: uint16(msg.Cols)}
				if err := pty.Setsize(ptyfile, ws); err != nil {
					log.Printf("failed to resize pty: %v", err)
				}
			}
		}
	}
}

//go:embed webshell.html
var webshellHtml string
