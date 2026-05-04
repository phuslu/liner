package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/smallnest/ringbuffer"
)

var _ Dialer = (*HTTP3Dialer)(nil)

type HTTP3Dialer struct {
	Username  string
	Password  string
	Host      string
	Port      string
	UserAgent string
	Insecure  bool
	Resolve   string
	Websocket bool
	TLSCache  *TLSClientSessionCache
	Logger    *slog.Logger

	mu        sync.Mutex
	transport *http3.Transport
}

func (d *HTTP3Dialer) init() {
	if d.transport != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.transport != nil {
		return
	}

	d.transport = &http3.Transport{
		DisableCompression: false,
		EnableDatagrams:    true,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx,
				net.JoinHostPort(cmp.Or(d.Resolve, d.Host), cmp.Or(d.Port, "443")),
				&tls.Config{
					NextProtos:         []string{"h3"},
					InsecureSkipVerify: d.Insecure,
					ServerName:         d.Host,
					ClientSessionCache: d.TLSCache,
				},
				&quic.Config{
					DisablePathMTUDiscovery:    false,
					EnableDatagrams:            true,
					MaxIncomingUniStreams:      200,
					MaxIncomingStreams:         200,
					MaxStreamReceiveWindow:     12 * 1024 * 1024,
					MaxConnectionReceiveWindow: 100 * 1024 * 1024,
				},
			)
		},
	}

	if d.UserAgent == "" {
		d.UserAgent = DefaultUserAgent
	}
}

func (d *HTTP3Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.init()

	pr, pw := ringbuffer.New(32 * 1024).Pipe()
	req := &http.Request{
		ProtoMajor: 3,
		Method:     http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   addr,
		},
		Host: addr,
		Header: http.Header{
			"content-type":        []string{"application/octet-stream"},
			"user-agent":          []string{d.UserAgent},
			"x-forwarded-network": []string{network},
		},
		Body:          pr,
		ContentLength: -1,
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		if d.Logger != nil {
			d.Logger.Debug("http3 dialer set extras headers", "dialer_http_header", header)
		}
		for key, values := range header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	if d.Username != "" && d.Password != "" {
		req.Header.Set("proxy-authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.Username+":"+d.Password)))
	}

	if d.Websocket {
		// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-connect-tcp-05
		key := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%x%x\n", fastrandn(1<<32-1), fastrandn(1<<32-1)))
		i := strings.LastIndexByte(addr, ':')
		req.URL.Path = fmt.Sprintf(HTTPTunnelConnectTCPPathPrefix+"%s/%s/", addr[:i], addr[i+1:])
		req.URL.Host = d.Host
		req.Host = d.Host
		req.Method = http.MethodConnect
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", key)
		if d.Logger != nil {
			d.Logger.Debug("http3dialer websocket request", "req_url", req.URL, "req_header", req.Header)
		}
	}

	var remoteAddr, localAddr net.Addr
	var quicConn *quic.Conn
	// The caller context bounds CONNECT setup; the returned stream must outlive it.
	streamCtx, streamCancel := context.WithCancel(context.WithoutCancel(ctx))
	stopDialCancel := context.AfterFunc(ctx, streamCancel)

	req = req.WithContext(httptrace.WithClientTrace(streamCtx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
			// see https://github.com/quic-go/quic-go/blob/master/http3/trace.go
			if data := (*[2]unsafe.Pointer)(unsafe.Pointer(&connInfo.Conn))[1]; data != nil {
				type fakeConn struct{ conn *quic.Conn }
				quicConn = (*fakeConn)(data).conn
			}
		},
	}))

	resp, err := d.transport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: false})
	if err != nil {
		stopDialCancel()
		streamCancel()
		_ = pw.CloseWithError(err)
		// if errmsg := err.Error(); strings.Contains(errmsg, "timeout: ") || strings.Contains(errmsg, "context deadline exceeded") || strings.Contains(errmsg, "context canceled") {
		// 	if d.Logger != nil {
		// 		d.Logger.Warn("close underlying http3 connection", "error", err)
		// 	}
		// }
		return nil, err
	}
	if !stopDialCancel() {
		_ = resp.Body.Close()
		streamCancel()
		if err := ctx.Err(); err != nil {
			_ = pw.CloseWithError(err)
			return nil, err
		}
		_ = pw.CloseWithError(context.Canceled)
		return nil, context.Canceled
	}

	if d.Logger != nil {
		d.Logger.Debug("http3dialer websocket response", "resp_statuscode", resp.StatusCode, "resp_header", resp.Header)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		streamCancel()
		err := errors.New("proxy: read from " + d.Host + " error: " + resp.Status + ": " + string(data))
		_ = pw.CloseWithError(err)
		return nil, err
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.UDPAddr{}, &net.UDPAddr{}
	}

	return &http3Stream{
		r:          resp.Body,
		w:          pw,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		quicConn:   quicConn,
		cancel: &httpStreamCancel{
			cancel:    streamCancel,
			closeRead: func(error) error { return resp.Body.Close() },
			closeWrite: func(err error) error {
				if err != nil {
					return pw.CloseWithError(err)
				}
				return pw.Close()
			},
		},
	}, nil
}

type http3Stream struct {
	r io.ReadCloser
	w io.Writer

	remoteAddr net.Addr
	localAddr  net.Addr
	quicConn   *quic.Conn
	cancel     *httpStreamCancel
}

func (c *http3Stream) Read(b []byte) (n int, err error) {
	n, err = c.r.Read(b)
	return n, c.cancel.ReadError(err)
}

func (c *http3Stream) Write(b []byte) (n int, err error) {
	n, err = c.w.Write(b)
	return n, c.cancel.WriteError(err)
}

func (c *http3Stream) Close() (err error) {
	return c.cancel.Close()
}

func (c *http3Stream) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3Stream) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http3Stream) SetDeadline(t time.Time) error {
	return c.cancel.SetDeadline(t)
}

func (c *http3Stream) SetReadDeadline(t time.Time) error {
	return c.cancel.SetReadDeadline(t)
}

func (c *http3Stream) SetWriteDeadline(t time.Time) error {
	return c.cancel.SetWriteDeadline(t)
}

func (c *http3Stream) QuicConn() *quic.Conn {
	return c.quicConn
}
