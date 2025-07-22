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
	"time"

	"github.com/phuslu/log"
)

type StreamRequest struct {
	RemoteAddr netip.AddrPort
	RemoteIP   string
	ServerAddr netip.AddrPort
	TraceID    log.XID
}

type StreamHandler struct {
	Config      StreamConfig
	DataLogger  log.Logger
	GeoResolver *GeoResolver
	LocalDialer *LocalDialer
	Dialers     map[string]Dialer

	tlsConfig *tls.Config
}

func (h *StreamHandler) Load() error {
	keyfile, certfile := h.Config.Keyfile, h.Config.Certfile
	if certfile == "" {
		certfile = keyfile
	}

	if keyfile == "" {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return err
	}

	h.tlsConfig = &tls.Config{
		MaxVersion:               tls.VersionTLS13,
		MinVersion:               tls.VersionTLS10,
		Certificates:             []tls.Certificate{cert},
		PreferServerCipherSuites: true,
	}

	return nil
}

func (h *StreamHandler) ServeConn(conn net.Conn) {
	ctx := context.Background()

	defer conn.Close()

	var req StreamRequest
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		req.RemoteAddr = addr.AddrPort()
	} else {
		req.RemoteAddr, _ = netip.ParseAddrPort(conn.RemoteAddr().String())
	}
	req.RemoteIP = req.RemoteAddr.Addr().String()
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		req.ServerAddr = addr.AddrPort()
	} else {
		req.ServerAddr, _ = netip.ParseAddrPort(conn.LocalAddr().String())
	}
	req.TraceID = log.NewXID()

	if tc, _ := conn.(*net.TCPConn); conn != nil && h.Config.SpeedLimit > 0 {
		err := SetTcpMaxPacingRate(tc, int(h.Config.SpeedLimit))
		log.DefaultLogger.Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).Str("remote_ip", req.RemoteIP).Str("stream_dialer_name", h.Config.Dialer).Int64("stream_speedlimit", h.Config.SpeedLimit).Msg("set speedlimit")
	}

	if h.tlsConfig != nil {
		tconn := tls.Server(conn, h.tlsConfig)
		err := tconn.HandshakeContext(ctx)
		if err != nil {
			log.Error().Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).Str("remote_ip", req.RemoteIP).Str("stream_dialer_name", h.Config.Dialer).Msg("connect remote host failed")
			return
		}
		conn = tconn
	}

	dail := h.LocalDialer.DialContext
	if h.Config.Dialer != "" {
		dialer, ok := h.Dialers[h.Config.Dialer]
		if !ok {
			log.Error().NetIPAddrPort("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("stream_dialer_name", h.Config.Dialer).Msg("dialer not exists")
			return
		}
		dail = dialer.DialContext
	}

	rconn, err := func(ctx context.Context) (net.Conn, error) {
		ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
			"X-Forwarded-For": []string{req.RemoteIP},
		})
		if h.Config.DialTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.DialTimeout)*time.Second)
			defer cancel()
		}
		if !strings.Contains(h.Config.ProxyPass, "://") {
			return dail(ctx, "tcp", h.Config.ProxyPass)
		}
		u, err := url.Parse(h.Config.ProxyPass)
		if err != nil {
			return nil, err
		}
		switch u.Scheme {
		case "unix", "unixgram":
			return dail(ctx, u.Scheme, u.Path)
		default:
			return dail(ctx, u.Scheme, u.Host)
		}
	}(ctx)
	if err != nil {
		log.Error().Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).Str("remote_ip", req.RemoteIP).Str("stream_dialer_name", h.Config.Dialer).Msg("connect remote host failed")
		return
	}
	defer rconn.Close()

	log.Info().Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("proxy_pass", h.Config.ProxyPass).Str("stream_dialer_name", h.Config.Dialer).Msg("forward stream")

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, rconn)

	if h.Config.Log {
		var country, city string
		if h.GeoResolver.CityReader != nil {
			country, city, _ = h.GeoResolver.LookupCity(ctx, net.ParseIP(req.RemoteIP))
		}
		h.DataLogger.Log().Str("logger", "stream").Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_city", city).Str("stream_dialer_name", h.Config.Dialer).Msg("")
	}

	return
}
