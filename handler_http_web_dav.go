package main

import (
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

	userloader *FileLoader[[]UserInfo]
	dav        *webdav.Handler
}

func (h *HTTPWebDavHandler) Load() (err error) {
	root := h.Root
	if root == "" {
		root = "/"
	}

	if strings.HasSuffix(h.AuthTable, ".csv") {
		h.userloader = GetUserInfoCsvLoader(h.AuthTable)
		records := h.userloader.Load()
		if records == nil {
			log.Fatal().Str("webdav_root", root).Str("auth_table", h.AuthTable).Msg("load auth_table failed")
		}
		log.Info().Str("webdav_root", root).Str("auth_table", h.AuthTable).Int("auth_table_size", len(*records)).Msg("load auth_table ok")
	}

	h.dav = &webdav.Handler{
		FileSystem: webdav.Dir(root),
		LockSystem: webdav.NewMemLS(),
	}

	return
}

func (h *HTTPWebDavHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)
	log.Info().Context(ri.LogContext).Any("headers", req.Header).Msg("web dav request")

	if h.userloader != nil {
		err := LookupUserInfoFromCsvLoader(h.userloader, &ri.AuthUserInfo)
		if err == nil {
			if allow, _ := ri.AuthUserInfo.Attrs["allow_webdav"].(string); allow != "1" {
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

	if strings.Contains(req.RequestURI, "..") {
		http.Error(rw, "404 Bad Request: "+req.RequestURI, http.StatusBadRequest)
		return
	}

	h.dav.ServeHTTP(rw, req)
}
