package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/phuslu/log"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (h *TunnelHandler) h3tunnel(ctx context.Context, dialerName, dialerURL string) (net.Listener, error) {
	log.Info().Str("dialer_name", dialerName).Msg("connecting tunnel host")

	u, err := url.Parse(dialerURL)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer %s: %s", dialerName, dialerURL)
	}

	transport := &http3.Transport{
		DisableCompression: false,
		EnableDatagrams:    true,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, err := quic.DialAddrEarly(ctx,
				net.JoinHostPort(cmp.Or(u.Query().Get("resolve"), u.Hostname()), cmp.Or(u.Port(), "443")),
				&tls.Config{
					NextProtos:         []string{"h3"},
					InsecureSkipVerify: u.Query().Get("insecure") == "true",
					ServerName:         u.Hostname(),
				},
				&quic.Config{
					DisablePathMTUDiscovery:    false,
					EnableDatagrams:            true,
					KeepAlivePeriod:            15 * time.Second,
					MaxIdleTimeout:             46 * time.Second,
					MaxIncomingUniStreams:      128,
					MaxIncomingStreams:         1024,
					MaxStreamReceiveWindow:     2 * 1024 * 1024,
					MaxConnectionReceiveWindow: 256 * 1024 * 1024,
				},
			)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}

	targetHost, targetPort, err := net.SplitHostPort(h.Config.RemoteListen[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote_listen addr: %s", h.Config.RemoteListen[0])
	}

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	reqCtx, reqCancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, "https://"+u.Host, nil)
	if err != nil {
		reqCancel()
		return nil, err
	}
	req.Header.Set("location", HTTPTunnelReverseTCPPathPrefix+targetHost+"/"+targetPort+"/")
	req.Header.Set("content-type", "application/octet-stream")
	req.Header.Set("user-agent", TunnelUserAgent)
	if u.User != nil {
		req.Header.Set("authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+first(u.User.Password()))))
	}
	if u.Query().Get("websocket") == "true" {
		req.Method = http.MethodConnect
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

	var quicConn *quic.Conn

	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			// see https://github.com/quic-go/quic-go/blob/master/http3/trace.go
			if data := (*[2]unsafe.Pointer)(unsafe.Pointer(&connInfo.Conn))[1]; data != nil {
				type fakeConn struct{ conn *quic.Conn }
				quicConn = (*fakeConn)(data).conn
			}
		},
	}))

	resp, err := transport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: false})
	if err != nil {
		if errmsg := err.Error(); strings.Contains(errmsg, "timeout: ") || strings.Contains(errmsg, "context deadline exceeded") || strings.Contains(errmsg, "context canceled") {
			log.Warn().Err(err).Msg("close underlying http3 connection")
		}
		reqCancel()
		transport.Close()
		return nil, err
	}

	log.Debug().Int("resp_statuscode", resp.StatusCode).Any("resp_header", resp.Header).Msg("http3dialer websocket response")

	if (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols) || quicConn == nil {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		reqCancel()
		return nil, fmt.Errorf("http3tunnel: read from %s(%+v) error: %v: %s", u.Host, quicConn, resp.Status, data)
	}

	ln := NewQUICReverseListener(ctx, quicConn, resp.Body, reqCancel)
	return &TunnelListener{
		Listener: ln,
		closer:   transport,
		ctx:      quicConn.Context(),
	}, nil
}

var _ net.Listener = (*QUICReverseListener)(nil)

type QUICReverseListener struct {
	conn   *quic.Conn
	body   io.ReadCloser
	cancel context.CancelFunc
	ctx    context.Context
	stop   context.CancelFunc
	once   sync.Once
}

func NewQUICReverseListener(parent context.Context, conn *quic.Conn, body io.ReadCloser, cancel context.CancelFunc) *QUICReverseListener {
	ctx, stop := context.WithCancel(parent)
	ln := &QUICReverseListener{
		conn:   conn,
		body:   body,
		cancel: cancel,
		ctx:    ctx,
		stop:   stop,
	}
	go ln.watchControl()
	return ln
}

func (ln *QUICReverseListener) Accept() (net.Conn, error) {
	stream, err := ln.conn.AcceptStream(ln.ctx)
	if err != nil {
		return nil, err
	}
	var b [4]byte
	if _, err := io.ReadFull(stream, b[:]); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, err
	}
	if b2s(b[:]) != HTTP3TunnelOpenFrame {
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, fmt.Errorf("quic reverse stream: invalid open frame %x", b)
	}
	log.Debug().NetAddr("remote_addr", ln.conn.RemoteAddr()).Int64("quic_stream_id", int64(stream.StreamID())).Msg("quic reverse stream accept conn")
	return &QuicStreamConn{
		stream: stream,
		laddr:  ln.conn.LocalAddr(),
		raddr:  ln.conn.RemoteAddr(),
	}, nil
}

func (ln *QUICReverseListener) Addr() net.Addr {
	return ln.conn.LocalAddr()
}

func (ln *QUICReverseListener) Close() error {
	ln.close()
	return nil
}

func (ln *QUICReverseListener) watchControl() {
	if ln.body != nil {
		_, _ = io.Copy(io.Discard, ln.body)
	}
	ln.close()
}

func (ln *QUICReverseListener) close() {
	ln.once.Do(func() {
		ln.stop()
		if ln.cancel != nil {
			ln.cancel()
		}
		if ln.body != nil {
			_ = ln.body.Close()
		}
	})
}
