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
	"sync"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/phuslu/log"
	utls "github.com/refraction-networking/utls"
	"github.com/smallnest/ringbuffer"
	"golang.org/x/net/http2"
)

func (h *TunnelHandler) h2tunnel(ctx context.Context, dialer string) (net.Listener, error) {
	log.Info().Str("dialer", dialer).Msg("connecting tunnel host")

	u, err := url.Parse(dialer)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer: %s", dialer)
	}

	transport := &http2.Transport{
		MaxReadFrameSize:   1024 * 1024, // 1MB read frame, https://github.com/golang/go/issues/47840
		DisableCompression: false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			hostport := net.JoinHostPort(u.Hostname(), cmp.Or(u.Port(), "443"))
			dialer := h.LocalDialer
			if m, ok := ctx.Value(DialerMemoryDialersContextKey).(*sync.Map); ok && m != nil {
				if d, ok := m.Load(hostport); ok && d != nil {
					if md, ok := d.(*MemoryDialer); ok && md != nil {
						dialer = md
					}
				}
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

			if tc, _ := conn.(*net.TCPConn); conn != nil && h.Config.SpeedLimit > 0 {
				err := (ConnOps{tc, nil}).SetTcpMaxPacingRate(int(h.Config.SpeedLimit))
				log.DefaultLogger.Err(err).Str("tunnel_proxy_pass", h.Config.ProxyPass).Str("tunnel_dialer_name", h.Config.Dialer).Int64("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set speedlimit")
			}

			tlsConfig := &utls.Config{
				NextProtos:         []string{"h2"},
				InsecureSkipVerify: u.Query().Get("insecure") == "true",
				ServerName:         u.Hostname(),
				ClientSessionCache: utls.NewLRUClientSessionCache(1024),
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
	req.Header.Set("user-agent", DefaultUserAgent)
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

	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
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
		remoteAddr, localAddr = &net.UDPAddr{}, &net.UDPAddr{}
	}

	conn := &http2Stream{
		r:          resp.Body,
		w:          pw,
		closed:     make(chan struct{}),
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
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
		return nil, fmt.Errorf("tunnel: open yamux server on remote %s: %w", h.Config.RemoteListen[0], err)
	}

	return &TunnelListener{
		Listener: ln,
		closer:   conn,
		ctx:      nil,
	}, nil
}
