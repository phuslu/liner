package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"text/template"

	"github.com/phuslu/log"
)

type RedsocksRequest struct {
	RemoteAddr netip.AddrPort
	ServerAddr netip.AddrPort
	Host       string
	Port       uint16
	TraceID    log.XID
}

type RedsocksHandler struct {
	Config      RedsocksConfig
	DataLogger  log.Logger
	GeoResolver *GeoResolver
	LocalDialer *LocalDialer
	Dialers     map[string]Dialer
	Functions   template.FuncMap

	dialer *template.Template
}

func (h *RedsocksHandler) Load() error {
	var err error

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

	tc, ok := conn.(*net.TCPConn)
	if !ok {
		log.Error().Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("failed to convert remote connection to tcp connection")
		return
	}

	addrport, err := (ConnOps{tc, nil}).GetOriginalDST()
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("failed to get original dst from remote tcp connection")
		return
	}
	req.Host, req.Port = addrport.Addr().String(), addrport.Port()

	var dialerName = h.Config.Forward.Dialer
	if h.dialer != nil {
		var sb strings.Builder
		err := h.dialer.Execute(&sb, struct {
			Request    RedsocksRequest
			ServerAddr netip.AddrPort
		}{req, req.ServerAddr})
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", addrport).Msg("failed to eval dialer template")
			return
		}
		dialerName = sb.String()
	}
	dialerName = strings.TrimSpace(dialerName)

	var dialer Dialer
	if dialerName != "" {
		if d, ok := h.Dialers[dialerName]; !ok {
			log.Error().Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", addrport).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dialer not exists")
			return
		} else {
			dialer = d
		}
	} else {
		dialer = h.LocalDialer
	}

	ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For": []string{req.RemoteAddr.Addr().String()},
	})
	rconn, err := dialer.DialContext(ctx, "tcp", addrport.String())
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", addrport).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dial host error")
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, rconn)

	if h.Config.Forward.Log {
		h.DataLogger.Log().
			Str("logger", "socks").
			Xid("trace_id", req.TraceID).
			NetIPAddrPort("server_addr", req.ServerAddr).
			NetIPAddr("remote_ip", req.RemoteAddr.Addr()).
			Str("redsocks_host", req.Host).
			Uint16("redsocks_port", req.Port).
			Str("forward_dialer_name", h.Config.Forward.Dialer).
			Str("forward_dialer_name", dialerName).
			Msg("")
	}

	return
}
