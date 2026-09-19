package main

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var _ Dialer = (*SSHDialer)(nil)

type SSHDialer struct {
	Username              string
	Password              string
	PrivateKey            string
	Host                  string
	Port                  string
	StrictHostKeyChecking bool
	UserKnownHostsFile    string
	Timeout               time.Duration
	IdleTimeout           time.Duration
	TcpReadBuffer         int
	TcpWriteBuffer        int
	Logger                *slog.Logger
	Dialer                Dialer

	mu     sync.Mutex
	client atomic.Pointer[ssh.Client]
}

func (d *SSHDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.ErrUnsupported
	}

	client, err := d.clientFor(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := client.DialContext(ctx, network, addr)
	if err == nil {
		return conn, nil
	}
	// A rejected channel means the target refused the connection while
	// the ssh transport is still healthy; reconnecting would not help.
	if _, ok := errors.AsType[*ssh.OpenChannelError](err); ok {
		return conn, err
	}
	// A canceled or expired context says nothing about the transport health.
	if ctx.Err() != nil {
		return conn, err
	}
	// Dropping the transport closes every channel multiplexed on it, so only
	// do it when the transport stopped answering requests.
	if d.alive(client) {
		return conn, err
	}

	next, err := d.reconnect(ctx, client)
	if err != nil {
		return nil, err
	}
	return next.DialContext(ctx, network, addr)
}

// clientFor returns the cached ssh client, establishing one when needed.
func (d *SSHDialer) clientFor(ctx context.Context) (*ssh.Client, error) {
	if c := d.client.Load(); c != nil {
		return c, nil
	}
	return d.reconnect(ctx, nil)
}

// reconnect replaces failed with a fresh ssh client. It is single flight: a
// caller that finds a client replaced by another goroutine reuses that one
// instead of tearing a healthy transport down again.
func (d *SSHDialer) reconnect(ctx context.Context, failed *ssh.Client) (*ssh.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c := d.client.Load(); c != nil && c != failed {
		return c, nil
	}
	// The caller context is commonly the one that just expired.
	dialctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cmp.Or(d.Timeout, 10*time.Second))
	defer cancel()
	c, err := d.connect(dialctx)
	if err != nil {
		return nil, err
	}
	old := d.client.Swap(c)
	go func() {
		_ = c.Wait()
		d.client.CompareAndSwap(c, nil)
	}()
	if old != nil && old != c {
		old.Close()
	}
	return c, nil
}

// alive reports whether the ssh transport still answers requests. A transport
// that does not answer within the timeout is closed so callers stop using it.
func (d *SSHDialer) alive(c *ssh.Client) bool {
	ch := make(chan error, 1)
	go func() {
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		ch <- err
	}()
	timer := time.NewTimer(min(cmp.Or(d.Timeout, 10*time.Second), 5*time.Second))
	defer timer.Stop()
	select {
	case err := <-ch:
		return err == nil
	case <-timer.C:
		c.Close()
		<-ch
		return false
	}
}

func (d *SSHDialer) connect(ctx context.Context) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: d.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(d.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cmp.Or(d.Timeout, 10*time.Second),
	}
	if d.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(d.PrivateKey))
		if err != nil {
			return nil, err
		}
		config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, config.Auth...)
	}
	if d.StrictHostKeyChecking {
		file := d.UserKnownHostsFile
		if file == "" {
			file = os.ExpandEnv("$HOME/.ssh/known_hosts")
		}
		cb, err := knownhosts.New(file)
		if err != nil {
			return nil, err
		}
		config.HostKeyCallback = cb
	}
	hostport := net.JoinHostPort(d.Host, cmp.Or(d.Port, "22"))
	dialer := d.Dialer
	if md := MemoryDialerOf(ctx, "tcp", hostport); md != nil {
		if d.Logger != nil {
			d.Logger.Info("ssh dialer switch to memory dialer", "memory_dialer_address", md.Address)
		}
		dialer = md
	}
	if dialer == nil {
		dialer = &net.Dialer{Timeout: config.Timeout}
	}
	dialctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	conn, err := dialer.DialContext(dialctx, "tcp", hostport)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if d.TcpReadBuffer > 0 {
			tc.SetReadBuffer(d.TcpReadBuffer)
		}
		if d.TcpWriteBuffer > 0 {
			tc.SetWriteBuffer(d.TcpWriteBuffer)
		}
	}
	if d.IdleTimeout > 0 {
		conn = &IdleTimeoutConn{
			Conn:        conn,
			IdleTimeout: d.IdleTimeout,
		}
	}
	// ClientConfig.Timeout is only honored by ssh.Dial, ssh.NewClientConn
	// needs an explicit deadline for the key exchange and authentication.
	conn.SetDeadline(time.Now().Add(config.Timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, hostport, config)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}
