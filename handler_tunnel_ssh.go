package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/phuslu/log"
	"golang.org/x/crypto/ssh"
)

func (h *TunnelHandler) sshtunnel(ctx context.Context, dialer string) (net.Listener, error) {
	log.Info().Str("dialer", dialer).Msg("connecting tunnel host")

	u, err := url.Parse(dialer)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer: %s", dialer)
	}

	config := &ssh.ClientConfig{
		User: u.User.Username(),
		Auth: []ssh.AuthMethod{
			ssh.Password(first(u.User.Password())),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         60 * time.Second,
	}
	if key := u.Query().Get("key"); key != "" {
		data, err := os.ReadFile(key)
		if err != nil {
			log.Error().Err(err).Msgf("failed to read ssh key %s", key)
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			log.Error().Err(err).Msgf("invalid ssh key %s", data)
			return nil, fmt.Errorf("invalid ssh key %s: %w", data, err)
		}
		config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, config.Auth...)
	}

	hostport := u.Host
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "22")
	}
	if resolve := u.Query().Get("resolve"); resolve != "" {
		_, port, _ := net.SplitHostPort(hostport)
		hostport = net.JoinHostPort(resolve, port)
	}

	conn, err := (&net.Dialer{Timeout: time.Duration(h.Config.DialTimeout) * time.Second}).DialContext(ctx, "tcp", hostport)
	if err != nil {
		log.Error().Err(err).Msgf("failed to dial %s", hostport)
		return nil, fmt.Errorf("failed to dial %s: %w", hostport, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, hostport, config)
	if err != nil {
		log.Error().Err(err).Msgf("failed to create ssh conn %s", hostport)
		return nil, fmt.Errorf("failed to create ssh conn %s: %w", hostport, err)
	}

	client := ssh.NewClient(c, chans, reqs)

	// Set up the remote listener
	ln, err := client.Listen("tcp", h.Config.Listen[0])
	if err != nil {
		log.Error().Err(err).Msgf("failed to listen %s", h.Config.Listen[0])
		client.Close()
		return nil, fmt.Errorf("failed to dial %s: %w", h.Config.Listen[0], err)
	}

	if tc, _ := conn.(*net.TCPConn); conn != nil && h.Config.SpeedLimit > 0 {
		err := (TCPConn{tc}).SetTcpMaxPacingRate(int(h.Config.SpeedLimit))
		log.DefaultLogger.Err(err).Str("tunnel_proxy_pass", h.Config.ProxyPass).Str("tunnel_dialer_name", h.Config.Dialer).Int64("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set speedlimit")
	}

	return &TunnelListener{ln, client}, nil
}
