package main

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/phuslu/log"
)

type HTTPWebShellHandler struct {
	AuthBasic string
	AuthTable string

	userchecker AuthUserChecker
	fileserver  http.Handler
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

	zipreader, err := zip.NewReader(bytes.NewReader(xtermZip), int64(len(xtermZip)))
	if err != nil {
		return err
	}
	h.fileserver = http.FileServer(http.FS(zipreader))

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
		http.Error(rw, "404 Bad Request: "+req.RequestURI, http.StatusBadRequest)
		return
	}

	h.fileserver.ServeHTTP(rw, req)
}

//go:embed xterm@5.3.0.zip
var xtermZip []byte
