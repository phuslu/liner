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

	connect := func(ctx context.Context) (*ssh.Client, error) {
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
		if md := MemoryDialerOf(ctx, network, hostport); md != nil {
			if d.Logger != nil {
				d.Logger.Info("ssh dialer switch to memory dialer", "memory_dialer_address", md.Address)
			}
			dialer = md
		}
		if dialer == nil {
			dialer = &net.Dialer{Timeout: config.Timeout}
		}
		ctx, cancel := context.WithTimeout(ctx, config.Timeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", hostport)
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
		c, chans, reqs, err := ssh.NewClientConn(conn, hostport, config)
		if err != nil {
			return nil, err
		}
		return ssh.NewClient(c, chans, reqs), nil
	}

	if d.client.Load() == nil {
		d.mu.Lock()
		if d.client.Load() == nil {
			c, err := connect(ctx)
			if err != nil {
				d.mu.Unlock()
				return nil, err
			}
			d.client.Store(c)
		}
		d.mu.Unlock()
	}

	conn, err := d.client.Load().DialContext(ctx, network, addr)
	if err != nil {
		// A rejected channel means the target refused the connection while
		// the ssh transport is still healthy; reconnecting would not help.
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			return conn, err
		}

		time.Sleep(time.Duration(100+fastrandn(200)) * time.Millisecond)
		old := d.client.Load()
		d.mu.Lock()
		replaced := false
		if d.client.Load() == old {
			c, cerr := connect(ctx)
			if cerr == nil {
				d.client.Store(c)
				replaced = true
			} else {
				err = cerr
			}
		}
		d.mu.Unlock()
		if replaced {
			old.Close()
			conn, err = d.client.Load().DialContext(ctx, network, addr)
		} else if c := d.client.Load(); c != nil && c != old {
			conn, err = c.DialContext(ctx, network, addr)
		}
	}

	return conn, err
}
