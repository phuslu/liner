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
	"github.com/quic-go/quic-go/quicvarint"
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
	udpClient *http3.ClientConn
	udpConn   *quic.Conn
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
			return d.dialQUIC(ctx)
		},
	}

	if d.UserAgent == "" {
		d.UserAgent = DefaultUserAgent
	}
}

func (d *HTTP3Dialer) dialQUIC(ctx context.Context) (*quic.Conn, error) {
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
}

func (d *HTTP3Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.init()

	switch network {
	case "tcp", "tcp4", "tcp6":
		return d.dialTCP(ctx, network, addr)
	case "udp", "udp4", "udp6":
		return d.dialUDP(ctx, network, addr)
	}

	return nil, errors.ErrUnsupported
}

func (d *HTTP3Dialer) dialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
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

	var quicConn *quic.Conn
	// The caller context bounds CONNECT setup; the returned stream must outlive it.
	streamCtx, streamCancel := context.WithCancel(context.WithoutCancel(ctx))
	stopDialCancel := context.AfterFunc(ctx, streamCancel)

	req = req.WithContext(httptrace.WithClientTrace(streamCtx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
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

	return &http3Stream{
		body: resp.Body,
		pipe: pw,
		conn: quicConn,
		closeRead: func(error) error {
			return resp.Body.Close()
		},
		closeWrite: func(err error) error {
			if err != nil {
				return pw.CloseWithError(err)
			}
			return pw.Close()
		},
		cancel: streamCancel,
	}, nil
}

func (d *HTTP3Dialer) dialUDP(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	cc, qconn, err := d.http3ClientConn(ctx)
	if err != nil {
		return nil, err
	}

	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-qconn.Context().Done():
		d.closeHTTP3ClientConn(qconn)
		return nil, context.Cause(qconn.Context())
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
			"user-agent":                []string{d.UserAgent},
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

	streamCtx, streamCancel := context.WithCancel(context.WithoutCancel(ctx))
	stopDialCancel := context.AfterFunc(ctx, streamCancel)

	stream, err := cc.OpenRequestStream(streamCtx)
	if err != nil {
		stopDialCancel()
		streamCancel()
		d.closeHTTP3ClientConn(qconn)
		return nil, err
	}
	req = req.WithContext(streamCtx)
	if err := stream.SendRequestHeader(req); err != nil {
		stopDialCancel()
		streamCancel()
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}

	resp, err := stream.ReadResponse()
	if err != nil {
		stopDialCancel()
		streamCancel()
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	if !stopDialCancel() {
		_ = resp.Body.Close()
		streamCancel()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
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

func (d *HTTP3Dialer) http3ClientConn(ctx context.Context) (*http3.ClientConn, *quic.Conn, error) {
	d.init()

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.udpClient != nil && d.udpConn != nil && d.udpConn.Context().Err() == nil {
		return d.udpClient, d.udpConn, nil
	}

	qconn, err := d.dialQUIC(ctx)
	if err != nil {
		return nil, nil, err
	}
	cc := d.transport.NewClientConn(qconn)
	d.udpClient = cc
	d.udpConn = qconn
	return cc, qconn, nil
}

func (d *HTTP3Dialer) closeHTTP3ClientConn(conn *quic.Conn) {
	d.mu.Lock()
	if d.udpConn == conn {
		d.udpClient = nil
		d.udpConn = nil
	}
	d.mu.Unlock()
	_ = conn.CloseWithError(0, "")
}

type http3Stream struct {
	body       io.ReadCloser
	pipe       io.Writer
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
	n, err = c.pipe.Write(b)
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
	return nil
}

func (c *http3Stream) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *http3Stream) SetWriteDeadline(t time.Time) error {
	return nil
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
	cancel     context.CancelFunc
	closeRead  func(error) error
	closeWrite func(error) error

	mu       sync.Mutex
	closed   bool
	readErr  error
	writeErr error
}

func (c *http3Datagram) Read(b []byte) (int, error) {
	for {
		data, err := c.stream.ReceiveDatagram(context.Background())
		if err != nil {
			return 0, c.readError(err)
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil || contextID != 0 {
			continue
		}
		return copy(b, data[n:]), nil
	}
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
	return nil
}

func (c *http3Datagram) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *http3Datagram) SetWriteDeadline(t time.Time) error {
	return nil
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
