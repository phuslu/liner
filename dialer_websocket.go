package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/phuslu/log"
)

var _ Dialer = (*WebsocketDialer)(nil)

type WebsocketDialer struct {
	EndpointFormat string // E.g. https://www.phus.lu/wss/connect?host=%s&port=%d
	Username       string
	Password       string
	UserAgent      string
	Dialer         Dialer
	TLSConfig      *tls.Config

	mu        sync.Mutex
	transport *http.Transport
}

func (d *WebsocketDialer) init() {
	if d.transport != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.transport != nil {
		return
	}

	d.transport = &http.Transport{
		DisableCompression: false,
		DialContext:        d.Dialer.DialContext,
		TLSClientConfig:    d.TLSConfig,
	}
	if len(d.transport.TLSClientConfig.NextProtos) != 0 && d.transport.TLSClientConfig.NextProtos[0] == "h2" {
		d.transport.TLSClientConfig = d.transport.TLSClientConfig.Clone()
		d.transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
}

func (d *WebsocketDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.init()

	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for Websocket proxy connections of type " + network)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(d.EndpointFormat, host, port), nil)
	if err != nil {
		return nil, err
	}

	if d.Username != "" && d.Password != "" {
		req.Header.Set("proxy-authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.Username+":"+d.Password)))
	}
	if d.UserAgent != "" {
		req.Header.Set("user-agent", d.UserAgent)
	}

	secWebsocketKey := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%x%x\n", log.Fastrandn(1<<32-1), log.Fastrandn(1<<32-1))))
	secWebsocketAccept := sha1.Sum([]byte(secWebsocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", secWebsocketKey)

	resp, err := d.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("proxy: failed to get greeting to HTTP proxy at %s: %d", host, resp.StatusCode)
	}

	if s := resp.Header.Get("Sec-WebSocket-Accept"); s != "" && s != base64.StdEncoding.EncodeToString(secWebsocketAccept[:]) {
		return nil, fmt.Errorf("proxy: failed to get sec-websocket-accept to HTTP proxy at " + host + ": " + s)
	}

	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		return nil, fmt.Errorf("proxy: failed to get io.ReadWriteCloser")
	}

	conn := &websocketStream{
		rwc:    rwc,
		local:  &net.TCPAddr{},
		remote: &net.TCPAddr{},
	}

	return conn, nil

}

type websocketStream struct {
	rwc    io.ReadWriteCloser
	local  net.Addr
	remote net.Addr
}

func (c *websocketStream) Read(b []byte) (n int, err error) {
	return c.rwc.Read(b)
}

func (c *websocketStream) Write(b []byte) (n int, err error) {
	return c.rwc.Write(b)
}

func (c *websocketStream) Close() (err error) {
	return c.rwc.Close()
}

func (c *websocketStream) LocalAddr() net.Addr {
	return c.local
}

func (c *websocketStream) RemoteAddr() net.Addr {
	return c.remote
}

func (c *websocketStream) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "websocket", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *websocketStream) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "websocket", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *websocketStream) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "websocket", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
