package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
	DnsResolver *DnsResolver
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

	addrportStr := addrport.String()

	tlsClientHello := func() (*tls.ClientHelloInfo, error) {
		data := make([]byte, 2048)
		n, err := conn.Read(data)
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("failed to peek data from remote tcp connection")
			return nil, err
		}
		data = data[:n]
		conn = &ConnWithData{conn, data}
		var clienthello *tls.ClientHelloInfo
		err = tls.Server(&ConnWithData{nil, data}, &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				clienthello = hello
				return nil, nil
			},
		}).HandshakeContext(ctx)
		if clienthello != nil {
			err = nil
		}
		return clienthello, err
	}

	// log.Printf("%#v\n", first(tlsClientHello()))

	var dialerValue = h.Config.Forward.Dialer
	if h.dialer != nil {
		var sb strings.Builder
		err := h.dialer.Execute(&sb, struct {
			Request        RedsocksRequest
			ServerAddr     netip.AddrPort
			TLSClientHello func() (*tls.ClientHelloInfo, error)
		}{req, req.ServerAddr, tlsClientHello})
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", addrport).Msg("failed to eval dialer template")
			return
		}
		dialerValue = sb.String()
	}
	dialerValue = strings.TrimSpace(dialerValue)

	var dialerName = dialerValue
	if strings.Contains(dialerValue, "=") {
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", addrport).Str("dialer_value", dialerValue).Msg("failed to parse dialer query")
			return
		}
		dialerName = u.Get("dialer")
		if s := u.Get("dialer-addrport-context"); s != "" {
			addrportStr = s
		}
	}

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

	rconn, err := dialer.DialContext(ctx, "tcp", addrportStr)
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", addrport).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dial host error")
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()

	go io.Copy(rconn, conn)
	_, _ = io.Copy(conn, rconn)

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
}
