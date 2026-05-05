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

	var netConn net.Conn
	// The caller context bounds CONNECT setup; the returned stream must outlive it.
	streamCtx, streamCancel := context.WithCancel(context.WithoutCancel(ctx))
	stopDialCancel := context.AfterFunc(ctx, streamCancel)

	req = req.WithContext(httptrace.WithClientTrace(streamCtx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
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
		cancel: streamCancel,
	}

	return conn, nil
}

type http2Stream struct {
	body       io.ReadCloser
	pipe       io.Writer
	conn       net.Conn
	closeRead  func(error) error
	closeWrite func(error) error
	cancel     context.CancelFunc

	mu       sync.Mutex
	closed   bool
	readErr  error
	writeErr error
}

func (c *http2Stream) Read(b []byte) (n int, err error) {
	n, err = c.body.Read(b)
	return n, c.readError(err)
}

func (c *http2Stream) Write(b []byte) (n int, err error) {
	n, err = c.pipe.Write(b)
	return n, c.writeError(err)
}

func (c *http2Stream) Close() (err error) {
	return c.closeWithError(net.ErrClosed)
}

func (c *http2Stream) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *http2Stream) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *http2Stream) SetDeadline(t time.Time) error {
	return nil
}

func (c *http2Stream) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *http2Stream) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *http2Stream) NetConn() net.Conn {
	return c.conn
}

func (c *http2Stream) readError(err error) error {
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

func (c *http2Stream) writeError(err error) error {
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

func (c *http2Stream) closeWithError(err error) error {
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
