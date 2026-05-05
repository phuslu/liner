package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/smallnest/ringbuffer"
	"golang.org/x/net/http2"
)

var _ Dialer = (*HTTP2Dialer)(nil)

type HTTP2Dialer struct {
	Username   string
	Password   string
	Host       string
	Port       string
	UserAgent  string
	Insecure   bool
	CACert     string
	ClientKey  string
	ClientCert string
	Resolve    string

	Logger   *slog.Logger
	TLSCache utls.ClientSessionCache
	Dialer   Dialer

	mu        sync.Mutex
	transport *http2.Transport
}

func (d *HTTP2Dialer) init() {
	if d.transport != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.transport != nil {
		return
	}

	if d.TLSCache == nil {
		d.TLSCache = utls.NewLRUClientSessionCache(32)
	}

	d.transport = &http2.Transport{
		DisableCompression: false,
		MaxReadFrameSize:   1024 * 1024, // 1MB read frame, https://github.com/golang/go/issues/47840
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			hostport := net.JoinHostPort(cmp.Or(d.Resolve, d.Host), cmp.Or(d.Port, "443"))
			dialer := d.Dialer
			if md := MemoryDialerOf(ctx, network, hostport); md != nil {
				if d.Logger != nil {
					d.Logger.Info("http2 dialer switch to memory dialer", "memory_dialer_address", md.Address)
				}
				dialer = md
			}
			if dialer == nil {
				dialer = &net.Dialer{}
			}
			conn, err := dialer.DialContext(ctx, "tcp", hostport)
			if err != nil {
				return nil, err
			}

			tlsConfig := &utls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				InsecureSkipVerify: d.Insecure,
				ServerName:         d.Host,
				ClientSessionCache: d.TLSCache,
			}
			if d.CACert != "" && d.ClientKey != "" && d.ClientCert != "" {
				caData, err := os.ReadFile(d.CACert)
				if err != nil {
					return nil, err
				}

				cert, err := utls.LoadX509KeyPair(d.ClientCert, d.ClientKey)
				if err != nil {
					return nil, err
				}

				tlsConfig = tlsConfig.Clone()
				tlsConfig.RootCAs = x509.NewCertPool()
				tlsConfig.RootCAs.AppendCertsFromPEM(caData)
				tlsConfig.Certificates = []utls.Certificate{cert}
			}

			tlsConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)

			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				return nil, err
			}

			return tlsConn, nil
		},
	}

	if d.UserAgent == "" {
		d.UserAgent = DefaultUserAgent
	}
}

func (d *HTTP2Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.init()

	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.ErrUnsupported
	}

	pr, pw := ringbuffer.New(32 * 1024).Pipe()
	req := &http.Request{
		ProtoMajor: 2,
		Method:     http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   addr,
		},
		Host: addr,
		Header: http.Header{
			"content-type": []string{"application/octet-stream"},
			"user-agent":   []string{d.UserAgent},
		},
		Body:          pr,
		ContentLength: -1,
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		for key, values := range header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	if d.Username != "" && d.Password != "" {
		req.Header.Set("proxy-authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.Username+":"+d.Password)))
	}

	var remoteAddr, localAddr net.Addr
	var netConn net.Conn
	// The caller context bounds CONNECT setup; the returned stream must outlive it.
	streamCtx, streamCancel := context.WithCancel(context.WithoutCancel(ctx))
	stopDialCancel := context.AfterFunc(ctx, streamCancel)

	req = req.WithContext(httptrace.WithClientTrace(streamCtx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
			netConn = connInfo.Conn
		},
	}))

	resp, err := d.transport.RoundTrip(req)
	if err != nil {
		stopDialCancel()
		streamCancel()
		_ = pw.CloseWithError(err)
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

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		streamCancel()
		err := errors.New("proxy: read from " + d.Host + " error: " + resp.Status + ": " + string(data))
		_ = pw.CloseWithError(err)
		return nil, err
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.TCPAddr{}, &net.TCPAddr{}
	}

	conn := &http2Stream{
		r:          resp.Body,
		w:          pw,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		netConn:    netConn,
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
	}

	return conn, nil
}

type http2Stream struct {
	r io.ReadCloser
	w io.Writer

	remoteAddr net.Addr
	localAddr  net.Addr
	netConn    net.Conn
	cancel     *httpStreamCancel
}

func (c *http2Stream) Read(b []byte) (n int, err error) {
	finish, err := c.cancel.beginRead()
	if err != nil {
		return 0, err
	}
	n, err = c.r.Read(b)
	if ferr := finish(); err == nil && ferr != nil {
		err = ferr
	}
	return n, c.cancel.ReadError(err)
}

func (c *http2Stream) Write(b []byte) (n int, err error) {
	finish, err := c.cancel.beginWrite()
	if err != nil {
		return 0, err
	}
	n, err = c.w.Write(b)
	if ferr := finish(); err == nil && ferr != nil {
		err = ferr
	}
	return n, c.cancel.WriteError(err)
}

func (c *http2Stream) Close() (err error) {
	return c.cancel.Close()
}

func (c *http2Stream) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http2Stream) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http2Stream) SetDeadline(t time.Time) error {
	return c.cancel.SetDeadline(t)
}

func (c *http2Stream) SetReadDeadline(t time.Time) error {
	return c.cancel.SetReadDeadline(t)
}

func (c *http2Stream) SetWriteDeadline(t time.Time) error {
	return c.cancel.SetWriteDeadline(t)
}

func (c *http2Stream) NetConn() net.Conn {
	return c.netConn
}

// httpStreamCancel makes CONNECT streams behave like net.Conn for close and deadlines.
// Deadlines are enforced only while an I/O call is active; setting an idle
// deadline must not turn into a fixed timer that closes a long-lived tunnel.
type httpStreamCancel struct {
	cancel     context.CancelFunc
	closeRead  func(error) error
	closeWrite func(error) error

	mu            sync.Mutex
	closed        bool
	readErr       error
	writeErr      error
	readDeadline  time.Time
	writeDeadline time.Time
	readActive    int
	writeActive   int
	readSeq       uint64
	writeSeq      uint64
	readTimer     *time.Timer
	writeTimer    *time.Timer
}

func (c *httpStreamCancel) Close() error {
	return c.closeWithError(net.ErrClosed)
}

func (c *httpStreamCancel) ReadError(err error) error {
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

func (c *httpStreamCancel) WriteError(err error) error {
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

func (c *httpStreamCancel) SetDeadline(t time.Time) error {
	return c.setDeadline(t, true, true)
}

func (c *httpStreamCancel) SetReadDeadline(t time.Time) error {
	return c.setDeadline(t, true, false)
}

func (c *httpStreamCancel) SetWriteDeadline(t time.Time) error {
	return c.setDeadline(t, false, true)
}

func (c *httpStreamCancel) setDeadline(t time.Time, read, write bool) error {
	var readSeq, writeSeq uint64
	var readNow, writeNow bool

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if read {
		c.readDeadline = t
		readSeq, readNow = c.armReadTimerLocked()
	}
	if write {
		c.writeDeadline = t
		writeSeq, writeNow = c.armWriteTimerLocked()
	}
	c.mu.Unlock()

	if readNow {
		_ = c.timeoutRead(readSeq)
	}
	if writeNow {
		_ = c.timeoutWrite(writeSeq)
	}
	return nil
}

func (c *httpStreamCancel) beginRead() (func() error, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.readErr != nil {
		err := c.readErr
		c.mu.Unlock()
		return nil, err
	}
	if deadlineExpired(c.readDeadline) {
		c.mu.Unlock()
		return nil, os.ErrDeadlineExceeded
	}
	c.readActive++
	_, fireNow := c.armReadTimerLocked()
	c.mu.Unlock()

	if fireNow {
		_ = c.finishRead()
		return nil, os.ErrDeadlineExceeded
	}
	return c.finishRead, nil
}

func (c *httpStreamCancel) beginWrite() (func() error, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.writeErr != nil {
		err := c.writeErr
		c.mu.Unlock()
		return nil, err
	}
	if deadlineExpired(c.writeDeadline) {
		c.mu.Unlock()
		return nil, os.ErrDeadlineExceeded
	}
	c.writeActive++
	_, fireNow := c.armWriteTimerLocked()
	c.mu.Unlock()

	if fireNow {
		_ = c.finishWrite()
		return nil, os.ErrDeadlineExceeded
	}
	return c.finishWrite, nil
}

func (c *httpStreamCancel) finishRead() error {
	c.mu.Lock()
	if c.readActive > 0 {
		c.readActive--
	}
	if c.readActive == 0 {
		c.stopReadTimerLocked()
	}
	err := c.readErr
	if err == nil && c.closed {
		err = net.ErrClosed
	}
	c.mu.Unlock()
	return err
}

func (c *httpStreamCancel) finishWrite() error {
	c.mu.Lock()
	if c.writeActive > 0 {
		c.writeActive--
	}
	if c.writeActive == 0 {
		c.stopWriteTimerLocked()
	}
	err := c.writeErr
	if err == nil && c.closed {
		err = net.ErrClosed
	}
	c.mu.Unlock()
	return err
}

func deadlineExpired(t time.Time) bool {
	return !t.IsZero() && !time.Now().Before(t)
}

func (c *httpStreamCancel) armReadTimerLocked() (uint64, bool) {
	c.stopReadTimerLocked()
	if c.readActive == 0 || c.readDeadline.IsZero() {
		return 0, false
	}
	c.readSeq++
	seq := c.readSeq
	if d := time.Until(c.readDeadline); d > 0 {
		c.readTimer = time.AfterFunc(d, func() {
			_ = c.timeoutRead(seq)
		})
		return 0, false
	}
	return seq, true
}

func (c *httpStreamCancel) armWriteTimerLocked() (uint64, bool) {
	c.stopWriteTimerLocked()
	if c.writeActive == 0 || c.writeDeadline.IsZero() {
		return 0, false
	}
	c.writeSeq++
	seq := c.writeSeq
	if d := time.Until(c.writeDeadline); d > 0 {
		c.writeTimer = time.AfterFunc(d, func() {
			_ = c.timeoutWrite(seq)
		})
		return 0, false
	}
	return seq, true
}

func (c *httpStreamCancel) stopReadTimerLocked() {
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
		c.readSeq++
	}
}

func (c *httpStreamCancel) stopWriteTimerLocked() {
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
		c.writeSeq++
	}
}

func (c *httpStreamCancel) timeoutRead(seq uint64) error {
	err := os.ErrDeadlineExceeded

	c.mu.Lock()
	if c.closed || c.readErr != nil || c.readActive == 0 || seq != c.readSeq {
		c.mu.Unlock()
		return nil
	}
	c.readErr = err
	c.stopReadTimerLocked()
	closeRead := c.closeRead
	c.mu.Unlock()

	if closeRead != nil {
		return closeRead(err)
	}
	return nil
}

func (c *httpStreamCancel) timeoutWrite(seq uint64) error {
	err := os.ErrDeadlineExceeded

	c.mu.Lock()
	if c.closed || c.writeErr != nil || c.writeActive == 0 || seq != c.writeSeq {
		c.mu.Unlock()
		return nil
	}
	c.writeErr = err
	c.stopWriteTimerLocked()
	closeWrite := c.closeWrite
	c.mu.Unlock()

	if closeWrite != nil {
		return closeWrite(err)
	}
	return nil
}

func (c *httpStreamCancel) closeWithError(err error) error {
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
	c.stopReadTimerLocked()
	c.stopWriteTimerLocked()
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
