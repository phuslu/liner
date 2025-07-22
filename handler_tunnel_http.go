package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/phuslu/log"
)

func (h *TunnelHandler) h1tunnel(ctx context.Context, dialer string) (net.Listener, error) {
	log.Info().Str("dialer", dialer).Msg("connecting tunnel host")

	ctx, cancel := context.WithTimeout(ctx, time.Duration(h.Config.DialTimeout)*time.Second)
	defer cancel()

	u, err := url.Parse(dialer)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer: %s", dialer)
	}

	host, port, ech := u.Hostname(), u.Port(), []byte{}
	if u.Query().Get("ech") == "true" {
		https, err := h.Resolver.LookupHTTPS(ctx, host)
		log.Debug().Str("dns_server", h.Resolver.Addr).Interface("https", https).AnErr("error", err).Msg("lookup https records")
		if len(https) == 0 && err == nil {
			err = fmt.Errorf("lookup https %v error: emtpy record", host)
		}
		if err != nil {
			log.Error().Err(err).Str("tunnel_host", host).Stringer("tunnel_url", u).Msg("lookup https error")
			return nil, err
		}
		if len(https[0].ECH) > 0 {
			ech = https[0].ECH
		}
		switch {
		case len(https[0].IPv4Hint) > 0:
			host = https[0].IPv4Hint[0].String()
		case len(https[0].IPv6Hint) > 0:
			host = https[0].IPv6Hint[0].String()
		}
	}
	if resolve := u.Query().Get("resolve"); resolve != "" {
		host = resolve
	}
	if _, err := netip.ParseAddr(host); err != nil {
		ips, err := h.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		host = ips[0].String()
	}
	if port == "" {
		switch u.Scheme {
		case "http,", "ws":
			port = "80"
		default:
			port = "443"
		}
	}

	hostport := net.JoinHostPort(host, port)

	conn, err := h.LocalDialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		log.Error().Err(err).Str("tunnel_host", hostport).Msg("connect tunnel host error")
		return nil, err
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		config := net.KeepAliveConfig{
			Enable:   true,
			Idle:     15 * time.Second,
			Interval: 15 * time.Second,
			Count:    3,
		}
		err := tc.SetKeepAliveConfig(config)
		log.DefaultLogger.Err(err).Str("tunnel_host", hostport).Any("keepalive_config", config).Msg("set tunnel host keepalive")
		if h.Config.SpeedLimit > 0 {
			err := SetTcpMaxPacingRate(tc, int(h.Config.SpeedLimit))
			log.DefaultLogger.Err(err).Str("tunnel_host", hostport).Any("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set tunnel speedlimit")
		}
	}

	switch u.Scheme {
	case "https", "wss":
		tlsConfig := &tls.Config{
			NextProtos:         []string{"http/1.1"},
			InsecureSkipVerify: u.Query().Get("insecure") == "true",
			ServerName:         u.Hostname(),
		}
		if len(ech) > 0 {
			tlsConfig.MinVersion = tls.VersionTLS13
			tlsConfig.EncryptedClientHelloConfigList = ech
		}
		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			_ = conn.Close()
			log.Error().Err(err).Str("tunnel_host", hostport).Msg("handshake tunnel host error")
			return nil, err
		}
		conn = tlsConn
	}

	targetHost, targetPort, err := net.SplitHostPort(h.Config.Listen[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote addr: %s", h.Config.Listen[0])
	}

	chacha20Key := u.Query().Get("chacha20_key")

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	buf := AppendableBytes(make([]byte, 0, 2048))
	if chacha20Key != "" {
		header := http.Header{}
		if username := u.User.Username(); username != "" {
			header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(s2b(username+":"+first(u.User.Password()))))
		}
		payload, _ := json.Marshal(struct {
			Time   int64       `json:"time"`
			Header http.Header `json:"header"`
			Method string      `json:"method"`
			URI    string      `json:"uri"`
		}{
			Time:   time.Now().Unix(),
			Header: header,
			Method: http.MethodGet,
			URI:    fmt.Sprintf("%s%s/%s/", HTTPTunnelReverseTCPPathPrefix, targetHost, targetPort),
		})
		cipher, nonce, err := Chacha20NewEncryptStreamCipher(s2b(chacha20Key))
		if err != nil {
			return nil, err
		}
		cipher.XORKeyStream(payload, payload)
		buf = buf.Str("GET ").Str(HTTPTunnelEncryptedPathPrefix).Hex(nonce).Byte('/').Base64(payload).Str(" HTTP/1.1\r\n")
	} else {
		buf = buf.Str("GET ").Str(HTTPTunnelReverseTCPPathPrefix).Str(targetHost).Byte('/').Str(targetPort).Str("/ HTTP/1.1\r\n")
	}
	buf = buf.Str("Host: ").Str(u.Hostname()).Str("\r\n")
	if chacha20Key == "" {
		buf = buf.Str("Authorization: Basic ").Base64(AppendableBytes(make([]byte, 0, 128)).Str(u.User.Username()).Byte(':').Str(first(u.User.Password()))).Str("\r\n")
	}
	buf = buf.Str("User-Agent: ").Str(DefaultUserAgent).Str("\r\n")
	switch u.Scheme {
	case "ws", "wss":
		buf = buf.Str("Connection: Upgrade\r\n")
		buf = buf.Str("Upgrade: websocket\r\n")
		buf = buf.Str("Sec-WebSocket-Version: 13\r\n")
		buf = buf.Str("Sec-WebSocket-Key: ").Base64(strconv.AppendUint(make([]byte, 0, 64), uint64(fastrandn(1<<32-1)), 10)).Str("\r\n")
	default:
		buf = buf.Str("Connection: Upgrade\r\n")
		buf = buf.Str("Upgrade: reverse\r\n")
	}
	buf = buf.Str("\r\n")

	log.Info().NetAddr("tunnel_conn_addr", conn.RemoteAddr()).Bytes("request_body", buf).Msg("send tunnel request")

	// conn.SetDeadline(time.Now().Add(time.Duration(h.Config.DialTimeout) * time.Second))
	_, err = conn.Write(buf)
	if err != nil {
		return nil, err
	}

	// see https://github.com/golang/go/issues/5373
	buf = buf[:cap(buf)]
	for i := range buf {
		buf[i] = 0
	}

	b := buf
	total := 0

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		total += n
		buf = buf[n:]

		if i := bytes.Index(b, CRLFCRLF); i > 0 {
			if i+4 < total {
				conn = &ConnWithData{conn, b[i+4 : total]}
			}
			break
		}
	}

	status := 0
	n := bytes.IndexByte(b, ' ')
	if n < 0 {
		return nil, fmt.Errorf("tunnel: failed to tunnel %s via %s: %s", h.Config.Listen[0], conn.RemoteAddr().String(), bytes.TrimRight(b, "\x00"))
	}
	for i, c := range b[n+1:] {
		if i == 3 || c < '0' || c > '9' {
			break
		}
		status = status*10 + int(c-'0')
	}
	if status != http.StatusOK && status != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("tunnel: failed to tunnel %s via %s: %s", h.Config.Listen[0], conn.RemoteAddr().String(), bytes.TrimRight(b, "\x00"))
	}

	ln, err := yamux.Server(conn, &yamux.Config{
		AcceptBacklog:           256,
		PingBacklog:             32,
		EnableKeepAlive:         h.Config.EnableKeepAlive,
		KeepAliveInterval:       30 * time.Second,
		MeasureRTTInterval:      30 * time.Second,
		ConnectionWriteTimeout:  10 * time.Second,
		MaxIncomingStreams:      1000,
		InitialStreamWindowSize: 256 * 1024,
		MaxStreamWindowSize:     16 * 1024 * 1024,
		LogOutput:               SlogWriter{Logger: log.DefaultLogger.Slog()},
		ReadBufSize:             4096,
		MaxMessageSize:          64 * 1024,
		WriteCoalesceDelay:      100 * time.Microsecond,
	}, nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel: open yamux server on remote %s: %w", h.Config.Listen[0], err)
	}

	return &TunnelListener{ln, conn}, nil
}
