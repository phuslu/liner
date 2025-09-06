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
	req.RemoteAddr = AddrPortFromNetAddr(conn.RemoteAddr())
	req.ServerAddr = AddrPortFromNetAddr(conn.LocalAddr())
	req.TraceID = log.NewXID()

	if tc, _ := conn.(*net.TCPConn); conn != nil && h.Config.SpeedLimit > 0 {
		err := (&TCPConn{tc}).SetTcpMaxPacingRate(int(h.Config.SpeedLimit))
		log.DefaultLogger.Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("stream_dialer_name", h.Config.Dialer).Int64("stream_speedlimit", h.Config.SpeedLimit).Msg("set speedlimit")
	}

	if h.tlsConfig != nil {
		tconn := tls.Server(conn, h.tlsConfig)
		err := tconn.HandshakeContext(ctx)
		if err != nil {
			log.Error().Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("stream_dialer_name", h.Config.Dialer).Msg("connect remote host failed")
			return
		}
		conn = tconn
	}

	dail := h.LocalDialer.DialContext
	if h.Config.Dialer != "" {
		dialer, ok := h.Dialers[h.Config.Dialer]
		if !ok {
			log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("stream_dialer_name", h.Config.Dialer).Msg("dialer not exists")
			return
		}
		dail = dialer.DialContext
	}

	rconn, err := func(ctx context.Context) (net.Conn, error) {
		ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
			"X-Forwarded-For": []string{req.RemoteAddr.Addr().String()},
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
		log.Error().Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("stream_dialer_name", h.Config.Dialer).Msg("connect remote host failed")
		return
	}
	defer rconn.Close()

	log.Info().Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("proxy_pass", h.Config.ProxyPass).Str("stream_dialer_name", h.Config.Dialer).Msg("forward stream")

	switch h.Config.ProxyProtocol {
	case 1:
		host, port, _ := net.SplitHostPort(h.Config.ProxyPass)
		b := AppendableBytes(make([]byte, 0, 64))
		if req.RemoteAddr.Addr().Is6() {
			b = b.Str("PROXY TCP6 ")
		} else {
			b = b.Str("PROXY TCP4 ")
		}
		b = b.NetIPAddr(req.RemoteAddr.Addr()).Byte(' ').Str(host).Byte(' ').Uint64(uint64(req.RemoteAddr.Port()), 10).Byte(' ').Str(port).Str("\r\n")
		_, err = rconn.Write(b)
		if err != nil {
			log.Error().Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Bytes("proxy_protocol_v1", b).Str("stream_dialer_name", h.Config.Dialer).Msg("write proxy protocol v1 header error")
			return
		}
	}

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, rconn)

	if h.Config.Log {
		var info GeoIPInfo
		if h.GeoResolver.CityReader != nil {
			info = h.GeoResolver.GetGeoIPInfo(ctx, req.RemoteAddr.Addr())
		}
		h.DataLogger.Log().
			Str("logger", "stream").
			Xid("trace_id", req.TraceID).
			NetIPAddrPort("server_addr", req.ServerAddr).
			NetIPAddr("remote_ip", req.RemoteAddr.Addr()).
			Str("remote_country", info.City).
			Str("remote_city", info.City).
			Str("remote_isp", info.ISP).
			Str("remote_connection_type", info.ConnectionType).
			Str("stream_dialer_name", h.Config.Dialer).
			Msg("")
	}

	return
}
