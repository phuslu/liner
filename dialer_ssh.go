package main

import (
	"cmp"
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

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
	MaxClients            int
	Timeout               time.Duration
	TcpReadBuffer         int
	TcpWriteBuffer        int
	Logger                *slog.Logger
	Dialer                Dialer

	mutexes [64]sync.Mutex
	clients [64]*ssh.Client
}

func (d *SSHDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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
		if m, ok := ctx.Value(DialerMemoryDialersContextKey).(*sync.Map); ok && m != nil {
			if v, ok := m.Load(hostport); ok && d != nil {
				if md, ok := v.(*MemoryDialer); ok && md != nil {
					if d.Logger != nil {
						d.Logger.Info("ssh dialer switch to memory dialer", "memory_dialer_address", md.Address)
					}
					dialer = md
				}
			}
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
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
		if err != nil {
			return nil, err
		}
		return ssh.NewClient(c, chans, reqs), nil
	}

	maxClient := d.MaxClients
	if maxClient == 0 {
		maxClient = 1
	}

	n := 1
	if 0 < maxClient && maxClient < len(d.clients) {
		n = maxClient
	}
	n = int(fastrandn(uint32(n)))

	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.clients[n]))) == nil {
		d.mutexes[n].Lock()
		if d.clients[n] == nil {
			c, err := connect(ctx)
			if err != nil {
				d.mutexes[n].Unlock()
				return nil, err
			}
			atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.clients[n])), unsafe.Pointer(c))
		}
		d.mutexes[n].Unlock()
	}

	conn, err := d.clients[n].DialContext(ctx, network, addr)
	if err != nil {
		time.Sleep(time.Duration(100+fastrandn(200)) * time.Millisecond)
		old := d.clients[n]
		d.mutexes[n].Lock()
		if d.clients[n] == old {
			d.clients[n], err = connect(ctx)
		}
		d.mutexes[n].Unlock()
		if c := d.clients[n]; c != nil && c != old {
			conn, err = c.DialContext(ctx, network, addr)
		}
	}

	return conn, err
}
