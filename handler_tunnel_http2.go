package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/phuslu/log"
	utls "github.com/refraction-networking/utls"
	"github.com/smallnest/ringbuffer"
	"golang.org/x/net/http2"
)

func (h *TunnelHandler) h2tunnel(ctx context.Context, dialerName, dialerURL string) (net.Listener, error) {
	log.Info().Str("dialer_name", dialerName).Msg("connecting tunnel host")

	u, err := url.Parse(dialerURL)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer %s: %s", dialerName, dialerURL)
	}

	transport := &http2.Transport{
		MaxReadFrameSize:   1024 * 1024, // 1MB read frame, https://github.com/golang/go/issues/47840
		DisableCompression: false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			hostport := net.JoinHostPort(cmp.Or(u.Query().Get("resolve"), u.Hostname()), cmp.Or(u.Port(), "443"))
			dialer := h.LocalDialer
			if md := MemoryDialerOf(ctx, network, hostport); md != nil {
				dialer = md
			}
			if dialer == nil {
				dialer = &net.Dialer{}
			}
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", hostport)
			if err != nil {
				return nil, err
			}

			if tc, _ := conn.(*net.TCPConn); conn != nil {
				if rate, _ := strconv.ParseUint(u.Query().Get("brutal_rate"), 10, 64); rate > 0 {
					err := (ConnOps{tc, nil}).SetTcpCongestion("brutal", uint64(rate), uint32(20))
					log.DefaultLogger.Err(err).Str("tunnel_proxy_pass", h.Config.ProxyPass).Str("tunnel_dialer_name", h.Config.Dialer).Uint64("tunnel_brutal_rate", rate).Msg("set tunnel brutal rate")
				} else if h.Config.SpeedLimit > 0 {
					err := (ConnOps{tc, nil}).SetTcpMaxPacingRate(int(h.Config.SpeedLimit))
					log.DefaultLogger.Err(err).Str("tunnel_proxy_pass", h.Config.ProxyPass).Str("tunnel_dialer_name", h.Config.Dialer).Int64("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set tunnel speedlimit")
				}
			}

			tlsConfig := &utls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				InsecureSkipVerify: u.Query().Get("insecure") == "true",
				ServerName:         u.Hostname(),
			}

			tlsConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)

			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				return nil, err
			}

			return tlsConn, nil
		},
	}

	targetHost, targetPort, err := net.SplitHostPort(h.Config.RemoteListen[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote_listen addr: %s", h.Config.RemoteListen[0])
	}

	pr, pw := ringbuffer.New(8192).Pipe()

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+u.Host+HTTPTunnelReverseTCPPathPrefix+targetHost+"/"+targetPort+"/", pr)
	if err != nil {
		return nil, err
	}
	req.ContentLength = -1
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("content-type", "application/octet-stream")
	req.Header.Set("user-agent", TunnelUserAgent)
	if u.User != nil {
		req.Header.Set("authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+first(u.User.Password()))))
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		log.Debug().Any("dialer_http_header", header).Msg("http2 dialer set extras headers")
		for key, values := range header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	var remoteAddr, localAddr net.Addr
	var netConn net.Conn

	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
			netConn = connInfo.Conn
		},
	}))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	log.Debug().Int("resp_statuscode", resp.StatusCode).Any("resp_header", resp.Header).Msg("http2 dialer websocket response")

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("proxy: read from " + u.Host + " error: " + resp.Status + ": " + string(data))
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.TCPAddr{}, &net.TCPAddr{}
	}

	conn := &http2Stream{
		body: resp.Body,
		pipe: pw,
		conn: netConn,
		closeRead: func(error) error {
			return resp.Body.Close()
		},
		closeWrite: func(err error) error {
			if err != nil {
				return pw.CloseWithError(err)
			}
			return pw.Close()
		},
		cancel: nil,
	}

	session, err := yamux.Server(conn, &yamux.Config{
		AcceptBacklog:           256,
		PingBacklog:             32,
		EnableKeepAlive:         true,
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
		return nil, fmt.Errorf("tunnel: open mux server on remote %s: %w", h.Config.RemoteListen[0], err)
	}

	return &TunnelListener{
		Listener: session,
		closer:   conn,
		ctx:      nil,
	}, nil
}
