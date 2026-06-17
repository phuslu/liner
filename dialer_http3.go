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
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
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

	mu   sync.Mutex
	conn atomic.Pointer[http3ClientConn]
}

const maxHTTP3DialRetries = 2

type http3ClientConn struct {
	client *http3.ClientConn
	conn   *quic.Conn
}

func (d *HTTP3Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return d.dialTCP(ctx, network, addr)
	case "udp", "udp4", "udp6":
		return d.dialUDP(ctx, network, addr)
	}

	return nil, errors.ErrUnsupported
}

func (d *HTTP3Dialer) dialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
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
			"user-agent":          []string{cmp.Or(d.UserAgent, DefaultUserAgent)},
			"x-forwarded-network": []string{network},
		},
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
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		key := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%x%x\n", fastrandn(1<<32-1), fastrandn(1<<32-1)))
		req.URL.Path = fmt.Sprintf(HTTPTunnelConnectTCPPathPrefix+"%s/%s/", host, port)
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

	var lastErr error
	for range maxHTTP3DialRetries {
		cc, qconn, err := d.dialClientConn(ctx)
		if err != nil {
			return nil, err
		}

		stream, resp, _, streamCancel, err := openHTTP3RequestStream(ctx, cc, req)
		if err != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			d.discardHTTP3ClientConn(qconn)
			lastErr = err
			if d.Logger != nil {
				d.Logger.Debug("http3 tcp dial retry after error", "error", err)
			}
			continue
		}

		if d.Logger != nil {
			d.Logger.Debug("http3dialer websocket response", "resp_statuscode", resp.StatusCode, "resp_header", resp.Header)
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			streamCancel()
			stream.CancelWrite(0)
			err := errors.New("proxy: read from " + d.Host + " error: " + resp.Status + ": " + string(data))
			return nil, err
		}

		return &http3Stream{
			body:   resp.Body,
			stream: stream,
			conn:   qconn,
			closeRead: func(error) error {
				stream.CancelRead(0)
				return resp.Body.Close()
			},
			closeWrite: func(err error) error {
				if err != nil {
					stream.CancelWrite(0)
				}
				return stream.Close()
			},
			cancel: streamCancel,
		}, nil
	}

	return nil, lastErr
}

func (d *HTTP3Dialer) dialUDP(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Proto:      "connect-udp",
		ProtoMajor: 3,
		ProtoMinor: 0,
		Method:     http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   d.Host,
			Path:   fmt.Sprintf(HTTPTunnelConnectUDPPathPrefix+"%s/%s/", host, port),
		},
		Host: d.Host,
		Header: http.Header{
			"user-agent":                []string{cmp.Or(d.UserAgent, DefaultUserAgent)},
			"x-forwarded-network":       []string{network},
			http3.CapsuleProtocolHeader: []string{"?1"},
		},
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		if d.Logger != nil {
			d.Logger.Debug("http3 udp dialer set extras headers", "dialer_http_header", header)
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

	var lastErr error
	for range maxHTTP3DialRetries {
		cc, qconn, err := d.dialClientConn(ctx)
		if err != nil {
			return nil, err
		}

		select {
		case <-cc.ReceivedSettings():
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-qconn.Context().Done():
			d.closeHTTP3ClientConn(qconn)
			lastErr = cmp.Or(context.Cause(qconn.Context()), qconn.Context().Err(), context.Canceled)
			if d.Logger != nil {
				d.Logger.Debug("http3 udp dial retry after stale quic conn", "error", lastErr)
			}
			continue
		}

		settings := cc.Settings()
		switch {
		case settings == nil:
			return nil, errors.New("http3: server settings unavailable")
		case !settings.EnableExtendedConnect:
			return nil, errors.New("http3: server didn't enable Extended CONNECT")
		case !settings.EnableDatagrams:
			return nil, errors.New("http3: server didn't enable HTTP Datagrams")
		}

		stream, resp, streamCtx, streamCancel, err := openHTTP3RequestStream(ctx, cc, req)
		if err != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			d.discardHTTP3ClientConn(qconn)
			lastErr = err
			if d.Logger != nil {
				d.Logger.Debug("http3 udp dial retry after error", "error", err)
			}
			continue
		}

		if d.Logger != nil {
			d.Logger.Debug("http3 udp dialer response", "resp_statuscode", resp.StatusCode, "resp_header", resp.Header)
		}

		if resp.StatusCode != http.StatusOK {
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			streamCancel()
			err := errors.New("proxy: read from " + d.Host + " error: " + resp.Status + ": " + string(data))
			return nil, err
		}

		return &http3Datagram{
			stream: stream,
			conn:   qconn,
			ctx:    streamCtx,
			cancel: streamCancel,
			closeRead: func(error) error {
				stream.CancelRead(0)
				return resp.Body.Close()
			},
			closeWrite: func(err error) error {
				if err != nil {
					stream.CancelWrite(0)
				}
				return stream.Close()
			},
		}, nil
	}

	return nil, lastErr
}

func openHTTP3RequestStream(ctx context.Context, cc *http3.ClientConn, req *http.Request) (*http3.RequestStream, *http.Response, context.Context, context.CancelFunc, error) {
	streamCtx, streamCancel := context.WithCancel(context.WithoutCancel(ctx))
	stopDialCancel := context.AfterFunc(ctx, streamCancel)

	stream, err := cc.OpenRequestStream(streamCtx)
	if err != nil {
		stopDialCancel()
		streamCancel()
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, nil, err
		}
		return nil, nil, nil, nil, err
	}
	stopDialCancel()

	cancelStream := func() {
		streamCancel()
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}
	stopRequestCancel := context.AfterFunc(ctx, cancelStream)

	if err := stream.SendRequestHeader(req.WithContext(streamCtx)); err != nil {
		stopRequestCancel()
		cancelStream()
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, nil, err
		}
		return nil, nil, nil, nil, err
	}

	resp, err := stream.ReadResponse()
	if err != nil {
		stopRequestCancel()
		cancelStream()
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, nil, err
		}
		return nil, nil, nil, nil, err
	}

	if !stopRequestCancel() {
		_ = resp.Body.Close()
		cancelStream()
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, nil, err
		}
		return nil, nil, nil, nil, context.Canceled
	}

	return stream, resp, streamCtx, streamCancel, nil
}

func (d *HTTP3Dialer) dialClientConn(ctx context.Context) (*http3.ClientConn, *quic.Conn, error) {
	if c := d.conn.Load(); c != nil && c.conn.Context().Err() == nil {
		return c.client, c.conn, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if c := d.conn.Load(); c != nil && c.conn.Context().Err() == nil {
		return c.client, c.conn, nil
	}

	qconn, err := d.dialQUICConn(ctx)
	if err != nil {
		return nil, nil, err
	}
	cc := (&http3.Transport{
		DisableCompression: false,
		EnableDatagrams:    true,
	}).NewClientConn(qconn)
	d.conn.Store(&http3ClientConn{client: cc, conn: qconn})
	return cc, qconn, nil
}

func (d *HTTP3Dialer) dialQUICConn(ctx context.Context) (*quic.Conn, error) {
	const concurrency = 2
	type connerr struct {
		conn *quic.Conn
		err  error
	}

	hostport := net.JoinHostPort(cmp.Or(d.Resolve, d.Host), cmp.Or(d.Port, "443"))
	var tlsCache tls.ClientSessionCache
	if d.TLSCache != nil {
		tlsCache = d.TLSCache
	}
	connc := make(chan *connerr, concurrency)
	conns := make([]*connerr, 0, concurrency)
	for range concurrency {
		go func() {
			conn, err := quic.DialAddrEarly(ctx,
				hostport,
				&tls.Config{
					NextProtos:         []string{"h3"},
					InsecureSkipVerify: d.Insecure,
					ServerName:         d.Host,
					ClientSessionCache: tlsCache,
				},
				&quic.Config{
					DisablePathMTUDiscovery:    false,
					EnableDatagrams:            true,
					KeepAlivePeriod:            15 * time.Second,
					MaxIdleTimeout:             46 * time.Second,
					MaxIncomingUniStreams:      200,
					MaxIncomingStreams:         200,
					MaxStreamReceiveWindow:     12 * 1024 * 1024,
					MaxConnectionReceiveWindow: 100 * 1024 * 1024,
				},
			)
			if err != nil {
				if d.Logger != nil {
					d.Logger.Debug("dial quic conn error", "hostport", hostport, "error", err)
				}
			} else {
				select {
				case <-conn.HandshakeComplete():
					if d.Logger != nil {
						d.Logger.Debug("dial quic conn ok", "hostport", hostport, "conn_rtt", conn.ConnectionStats().SmoothedRTT)
					}
				case <-conn.Context().Done():
					err = context.Cause(conn.Context())
					if err == nil {
						err = cmp.Or(conn.Context().Err(), context.Canceled)
					}
					conn = nil
					if d.Logger != nil {
						d.Logger.Debug("dial quic conn handshake error", "hostport", hostport, "error", err)
					}
				case <-ctx.Done():
					err = ctx.Err()
					_ = conn.CloseWithError(0, "")
					conn = nil
					if d.Logger != nil {
						d.Logger.Debug("dial quic conn handshake error", "hostport", hostport, "error", err)
					}
				}
			}
			connc <- &connerr{conn, err}
		}()
	}
	for range concurrency {
		c := <-connc
		conns = append(conns, c)
		if c.err != nil {
			continue
		}
		timer := time.NewTimer(200 * time.Millisecond)
		defer timer.Stop()
		for range concurrency - len(conns) {
			select {
			case c := <-connc:
				conns = append(conns, c)
			case <-timer.C:
				go func(n int) {
					for range n {
						c := <-connc
						if c.conn != nil {
							_ = c.conn.CloseWithError(0, "")
						}
					}
				}(concurrency - len(conns))
				goto scoring
			}
		}
		goto scoring
	}

scoring:
	slices.SortStableFunc(conns, func(c1, c2 *connerr) int {
		switch {
		case c1.err != nil && c2.err != nil:
			return 0
		case c1.err != nil:
			return 1
		case c2.err != nil:
			return -1
		default:
			return cmp.Compare(c1.conn.ConnectionStats().SmoothedRTT, c2.conn.ConnectionStats().SmoothedRTT)
		}
	})
	for _, c := range conns[1:] {
		if c.conn != nil {
			_ = c.conn.CloseWithError(0, "")
		}
	}
	if c := conns[0].conn; c != nil && d.Logger != nil {
		d.Logger.Debug("dial and pick quic conn ok", "remote_addr", c.RemoteAddr(), "local_addr", c.LocalAddr(), "conn_rtt", c.ConnectionStats().SmoothedRTT)
	}
	return conns[0].conn, conns[0].err
}

func (d *HTTP3Dialer) forgetHTTP3ClientConn(conn *quic.Conn) {
	for {
		c := d.conn.Load()
		if c == nil || c.conn != conn {
			return
		}
		if d.conn.CompareAndSwap(c, nil) {
			return
		}
	}
}

func (d *HTTP3Dialer) closeHTTP3ClientConn(conn *quic.Conn) {
	d.forgetHTTP3ClientConn(conn)
	_ = conn.CloseWithError(0, "")
}

func (d *HTTP3Dialer) discardHTTP3ClientConn(conn *quic.Conn) {
	if conn.Context().Err() != nil {
		d.closeHTTP3ClientConn(conn)
		return
	}
	d.forgetHTTP3ClientConn(conn)
}

type http3Stream struct {
	body       io.ReadCloser
	stream     *http3.RequestStream
	conn       *quic.Conn
	closeRead  func(error) error
	closeWrite func(error) error
	cancel     context.CancelFunc

	mu       sync.Mutex
	closed   bool
	readErr  error
	writeErr error
}

func (c *http3Stream) Read(b []byte) (n int, err error) {
	n, err = c.body.Read(b)
	return n, c.readError(err)
}

func (c *http3Stream) Write(b []byte) (n int, err error) {
	n, err = c.stream.Write(b)
	return n, c.writeError(err)
}

func (c *http3Stream) Close() (err error) {
	return c.closeWithError(net.ErrClosed)
}

func (c *http3Stream) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *http3Stream) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *http3Stream) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *http3Stream) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *http3Stream) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *http3Stream) QuicConn() *quic.Conn {
	return c.conn
}

func (c *http3Stream) readError(err error) error {
	if err == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return c.readErr
	}
	if c.closed {
		return net.ErrClosed
	}
	return err
}

func (c *http3Stream) writeError(err error) error {
	if err == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.closed {
		return net.ErrClosed
	}
	return err
}

func (c *http3Stream) closeWithError(err error) error {
	if err == nil {
		err = net.ErrClosed
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.readErr = err
	c.writeErr = err
	cancel := c.cancel
	closeRead := c.closeRead
	closeWrite := c.closeWrite
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	var closeReadErr, closeWriteErr error
	if closeRead != nil {
		closeReadErr = closeRead(err)
	}
	if closeWrite != nil {
		closeWriteErr = closeWrite(err)
	}
	return errors.Join(closeReadErr, closeWriteErr)
}

type http3Datagram struct {
	stream     *http3.RequestStream
	conn       *quic.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	closeRead  func(error) error
	closeWrite func(error) error

	readDeadline atomic.Int64

	mu       sync.Mutex
	closed   bool
	readErr  error
	writeErr error
}

func (c *http3Datagram) Read(b []byte) (int, error) {
	ctx, cancel, expired := c.readContext()
	if expired {
		return 0, c.readError(os.ErrDeadlineExceeded)
	}
	if cancel != nil {
		defer cancel()
	}
	for {
		data, err := c.stream.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				err = os.ErrDeadlineExceeded
			}
			return 0, c.readError(err)
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil || contextID != 0 {
			continue
		}
		return copy(b, data[n:]), nil
	}
}

func (c *http3Datagram) readContext() (context.Context, context.CancelFunc, bool) {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ns := c.readDeadline.Load()
	if ns == 0 {
		return ctx, nil, false
	}
	deadline := time.Unix(0, ns)
	if !deadline.After(time.Now()) {
		return ctx, nil, true
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	return ctx, cancel, false
}

func (c *http3Datagram) Write(b []byte) (int, error) {
	data := make([]byte, len(b)+1)
	copy(data[1:], b)
	if err := c.stream.SendDatagram(data); err != nil {
		var dtle *quic.DatagramTooLargeError
		if errors.As(err, &dtle) {
			return 0, err
		}
		return 0, c.writeError(err)
	}
	return len(b), nil
}

func (c *http3Datagram) Close() error {
	return c.closeWithError(net.ErrClosed)
}

func (c *http3Datagram) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *http3Datagram) LocalAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *http3Datagram) SetDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline.Store(0)
	} else {
		c.readDeadline.Store(t.UnixNano())
	}
	return c.stream.SetDeadline(t)
}

func (c *http3Datagram) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline.Store(0)
	} else {
		c.readDeadline.Store(t.UnixNano())
	}
	return c.stream.SetReadDeadline(t)
}

func (c *http3Datagram) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *http3Datagram) QuicConn() *quic.Conn {
	return c.conn
}

func (c *http3Datagram) readError(err error) error {
	if err == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return c.readErr
	}
	if c.closed {
		return net.ErrClosed
	}
	return err
}

func (c *http3Datagram) writeError(err error) error {
	if err == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.closed {
		return net.ErrClosed
	}
	return err
}

func (c *http3Datagram) closeWithError(err error) error {
	if err == nil {
		err = net.ErrClosed
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.readErr = err
	c.writeErr = err
	cancel := c.cancel
	closeRead := c.closeRead
	closeWrite := c.closeWrite
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	var closeReadErr, closeWriteErr error
	if closeRead != nil {
		closeReadErr = closeRead(err)
	}
	if closeWrite != nil {
		closeWriteErr = closeWrite(err)
	}
	return errors.Join(closeReadErr, closeWriteErr)
}
