package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/phuslu/log"
	"golang.org/x/net/webdav"
)

type HTTPWebDavHandler struct {
	Root      string
	AuthBasic string
	AuthTable string

	userchecker AuthUserChecker
	dav         *webdav.Handler
}

func (h *HTTPWebDavHandler) Load() (err error) {
	root := h.Root
	if root == "" {
		root = "/"
	}

	if table := h.AuthTable; table != "" {
		loader := NewAuthUserLoaderFromTable(table)
		records, err := loader.LoadAuthUsers(context.Background())
		if err != nil {
			log.Fatal().Err(err).Str("webdav_root", root).Str("auth_table", table).Msg("load auth_table failed")
		}
		log.Info().Str("webdav_root", root).Str("auth_table", table).Int("auth_table_size", len(records)).Msg("load auth_table ok")
		h.userchecker = &AuthUserLoadChecker{loader}
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

	if h.userchecker != nil {
		err := h.userchecker.CheckAuthUser(req.Context(), &ri.AuthUserInfo)
		if err == nil {
			if allow := ri.AuthUserInfo.Attrs["allow_webdav"]; allow != "1" {
				err = fmt.Errorf("webdav is not allow for user: %#v", ri.AuthUserInfo.Username)
			}
		}
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Any("user_attrs", ri.AuthUserInfo.Attrs).Msg("web dav auth error")
			rw.Header().Set("www-authenticate", `Basic realm="`+h.AuthBasic+`"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)

			return
		}
	}

	if strings.Contains(req.RequestURI, "../") || strings.Contains(req.RequestURI, "/..") {
		http.Error(rw, "400 Bad Request: "+req.RequestURI, http.StatusBadRequest)
		return
	}

	h.dav.ServeHTTP(rw, req)
}
