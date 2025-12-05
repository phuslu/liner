package main

import (
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/coder/websocket"
	"github.com/creack/pty"
	"github.com/phuslu/log"
)

type HTTPWebShellHandler struct {
	AuthBasic string
	AuthTable string
	Command   string

	userchecker AuthUserChecker
}

func (h *HTTPWebShellHandler) Load() error {
	if table := h.AuthTable; table != "" {
		loader := NewAuthUserLoaderFromTable(table)
		records, err := loader.LoadAuthUsers(context.Background())
		if err != nil {
			log.Fatal().Err(err).Str("auth_table", table).Msg("load auth_table failed")
		}
		log.Info().Str("auth_table", table).Int("auth_table_size", len(records)).Msg("load auth_table ok")
		h.userchecker = &AuthUserLoadChecker{loader}
	}

	return nil
}

func (h *HTTPWebShellHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)
	log.Info().Context(ri.LogContext).Any("headers", req.Header).Msg("web shell request")

	if h.userchecker != nil {
		err := h.userchecker.CheckAuthUser(req.Context(), &ri.AuthUserInfo)
		if err == nil {
			if allow := ri.AuthUserInfo.Attrs["allow_webshell"]; allow != "1" {
				err = fmt.Errorf("webshell is not allow for user: %#v", ri.AuthUserInfo.Username)
			}
		}
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Any("user_attrs", ri.AuthUserInfo.Attrs).Msg("web shell auth error")
			rw.Header().Set("www-authenticate", `Basic realm="`+h.AuthBasic+`"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)

			return
		}
	}

	if strings.Contains(req.RequestURI, "..") {
		http.Error(rw, "400 Bad Request: "+req.RequestURI, http.StatusBadRequest)
		return
	}

	if strings.HasSuffix(req.RequestURI, "/") {
		rw.Header().Set("content-type", "text/html; charset=utf-8")
		rw.Write(webshellHtml)
		return
	}

	switch filepath.Base(req.RequestURI) {
	case "xterm.min.js":
		rw.Header().Set("content-type", "application/javascript")
		rw.Write(xtermJS)
		return
	case "xterm.min.css":
		rw.Header().Set("content-type", "text/css")
		rw.Write(xtermCSS)
		return
	case "ws":
		break
	default:
		http.NotFound(rw, req)
		return
	}

	conn, err := websocket.Accept(rw, req, nil)
	if err != nil {
		http.Error(rw, "failed to accept websocket: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.CloseNow()

	cmd := exec.Command(cmp.Or(h.Command, "/bin/sh"))
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptyF, err := pty.Start(cmd)
	if err != nil {
		conn.Close(websocket.StatusInternalError, "failed to start pty")
		return
	}
	defer func() {
		_ = ptyF.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptyF.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("pty read error: %v", err)
				}
				return
			}
			err = conn.Write(context.Background(), websocket.MessageBinary, buf[:n])
			if err != nil {
				return
			}
		}
	}()

	for {
		typ, reader, err := conn.Reader(context.Background())
		if err != nil {
			log.Printf("ws read error: %v", err)
			return
		}

		if typ == websocket.MessageBinary {
			if _, err := io.Copy(ptyF, reader); err != nil {
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
				if err := pty.Setsize(ptyF, ws); err != nil {
					log.Printf("failed to resize pty: %v", err)
				}
			}
		}
	}
}

//go:embed webshell.html
var webshellHtml []byte

//go:embed xterm.min.css
var xtermCSS []byte

//go:embed xterm.min.js
var xtermJS []byte
