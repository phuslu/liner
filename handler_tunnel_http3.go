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
	"strings"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/phuslu/log"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/smallnest/ringbuffer"
)

func (h *TunnelHandler) h3tunnel(ctx context.Context, dialer string) (net.Listener, error) {
	log.Info().Str("dialer", dialer).Msg("connecting tunnel host")

	u, err := url.Parse(dialer)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer: %s", dialer)
	}

	transport := &http3.Transport{
		DisableCompression: false,
		EnableDatagrams:    true,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return quic.DialAddrEarly(ctx,
				net.JoinHostPort(cmp.Or(u.Query().Get("resolve"), u.Hostname()), cmp.Or(u.Port(), "443")),
				&tls.Config{
					NextProtos:         []string{"h3"},
					InsecureSkipVerify: u.Query().Get("insecure") == "true",
					ServerName:         u.Hostname(),
					ClientSessionCache: tls.NewLRUClientSessionCache(1024),
				},
				&quic.Config{
					DisablePathMTUDiscovery:    false,
					EnableDatagrams:            true,
					MaxIdleTimeout:             30 * time.Second,
					MaxIncomingUniStreams:      200,
					MaxIncomingStreams:         200,
					MaxStreamReceiveWindow:     6 * 1024 * 1024,
					MaxConnectionReceiveWindow: 100 * 1024 * 1024,
				},
			)
		},
	}

	targetHost, targetPort, err := net.SplitHostPort(h.Config.Listen[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote addr: %s", h.Config.Listen[0])
	}

	pr, pw := ringbuffer.New(8192).Pipe()

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+u.Host, pr)
	req.ContentLength = -1
	req.Header.Set("location", HTTPTunnelReverseTCPPathPrefix+targetHost+"/"+targetPort+"/")
	req.Header.Set("content-type", "application/octet-stream")
	req.Header.Set("user-agent", DefaultUserAgent)
	if u.User != nil {
		req.Header.Set("authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+first(u.User.Password()))))
	}
	if u.Query().Get("websocket") == "true" {
		req.Method = http.MethodPost
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", string(strconv.AppendUint(make([]byte, 0, 64), uint64(fastrandn(1<<32-1)), 10)))
	} else {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "reverse")
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		log.Debug().Any("dialer_http_header", header).Msg("http3 dialer set extras headers")
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

	resp, err := transport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: false})
	if err != nil {
		if errmsg := err.Error(); strings.Contains(errmsg, "timeout: ") || strings.Contains(errmsg, "context deadline exceeded") || strings.Contains(errmsg, "context canceled") {
			log.Warn().Err(err).Msg("close underlying http3 connection")
			transport.Close()
		}
		return nil, err
	}

	log.Debug().Int("resp_statuscode", resp.StatusCode).Any("resp_header", resp.Header).Msg("http3dialer websocket response")

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("proxy: read from " + u.Host + " error: " + resp.Status + ": " + string(data))
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.UDPAddr{}, &net.UDPAddr{}
	}

	conn := &http3Stream{
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
		return nil, fmt.Errorf("tunnel: open yamux server on remote %s: %w", h.Config.Listen[0], err)
	}

	return &TunnelListener{ln, conn}, nil
}
