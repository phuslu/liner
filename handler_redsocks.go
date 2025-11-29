package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"text/template"

	"github.com/phuslu/log"
)

type RedsocksRequest struct {
	RemoteAddr netip.AddrPort
	ServerAddr netip.AddrPort
	Host       string
	Port       int
	TraceID    log.XID
}

type RedsocksHandler struct {
	Config      RedsocksConfig
	DataLogger  log.Logger
	GeoResolver *GeoResolver
	LocalDialer *LocalDialer
	Dialers     map[string]Dialer
	Functions   template.FuncMap

	policy *template.Template
	dialer *template.Template
}

func (h *RedsocksHandler) Load() error {
	var err error

	h.Config.Forward.Policy = strings.TrimSpace(h.Config.Forward.Policy)
	if s := h.Config.Forward.Policy; strings.Contains(s, "{{") {
		if h.policy, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	h.Config.Forward.Dialer = strings.TrimSpace(h.Config.Forward.Dialer)
	if s := h.Config.Forward.Dialer; strings.Contains(s, "{{") {
		if h.dialer, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	return nil
}

func (h *RedsocksHandler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var req RedsocksRequest
	req.RemoteAddr = AddrPortFromNetAddr(conn.RemoteAddr())
	req.ServerAddr = AddrPortFromNetAddr(conn.LocalAddr())
	req.TraceID = log.NewXID()

	return
}
