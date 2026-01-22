package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/phuslu/log"
	"github.com/xtaci/smux"
)

type TunnelHandler struct {
	Config          TunnelConfig
	MemoryListeners *sync.Map // map[string]*MemoryListener
	DnsResolver     *DnsResolver
	LocalDialer     Dialer
	Dialers         map[string]string
}

func (h *TunnelHandler) Load() error {
	if len(h.Config.RemoteListen) != 1 {
		return fmt.Errorf("invalid tunnel remote listen: %v", h.Config.RemoteListen)
	}
	return nil
}

func (h *TunnelHandler) Serve(ctx context.Context) {
	loop := func(ctx context.Context) bool {
		dialer := h.Dialers[h.Config.Dialer]

		var ln net.Listener
		var err error
		switch strings.Split(dialer, "://")[0] {
		case "http", "https", "ws", "wss":
			ln, err = h.h1tunnel(ctx, dialer)
		case "http2":
			ln, err = h.h2tunnel(ctx, dialer)
		case "http3", "quic":
			ln, err = h.h3tunnel(ctx, dialer)
		case "ssh", "ssh2":
			ln, err = h.sshtunnel(ctx, dialer)
		default:
			log.Fatal().Str("dialer", dialer).Msg("dialer tunnel is unsupported")
		}
		if err != nil {
			log.Error().Err(err).Msgf("Failed to listen remote %s", h.Config.RemoteListen[0])
			time.Sleep(2 * time.Second)
			return true
		}

		defer ln.Close()

		log.Info().Msgf("Listening on remote %s", h.Config.RemoteListen[0])

		exit := make(chan error, 1)
		go func() {
			// Accept connections from the remote side
			for {
				rconn, err := ln.Accept()
				if err != nil || rconn == nil || reflect.ValueOf(rconn).IsNil() {
					exit <- err
					log.Error().Err(err).Any("rconn", rconn).Msg("Failed to accept remote connection")
					time.Sleep(10 * time.Millisecond)
					ln.Close()
					return
				}
				go h.handle(ctx, rconn, h.Config.ProxyPass)
			}
		}()

		var done <-chan struct{}
		if doner, ok := ln.(interface {
			Done() <-chan struct{}
		}); ok {
			done = doner.Done()
		}

		select {
		case <-exit:
			log.Info().Msg("tunnel listener accepting is exit")
		case <-done:
			log.Info().Msg("tunnel listener connection is done")
		}

		return true
	}

	last := time.Now()
	for loop(ctx) {
		delay := time.Duration(5+log.Fastrandn(10)) * time.Second
		if time.Since(last) > 1*time.Minute {
			delay = 2 * time.Second
		}
		log.Info().Dur("delay_ms", delay).Msg("tunnel loop...")
		time.Sleep(delay)
		last = time.Now()
	}
}

func (h *TunnelHandler) handle(ctx context.Context, rconn net.Conn, laddr string) {
	if h.MemoryListeners != nil {
		if v, ok := h.MemoryListeners.Load(h.Config.ProxyPass); ok && v != nil {
			ln, _ := v.(*MemoryListener)
			log.Info().NetAddr("remote_host", rconn.RemoteAddr()).NetAddr("local_addr", ln.Addr()).Msg("tunnel handler memory listener local addr")
			ln.SendConn(rconn)
			return
		}
	}

	defer rconn.Close()

	raddr := AddrPortFromNetAddr(rconn.RemoteAddr())
	ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For": []string{raddr.Addr().String()},
	})

	if h.Config.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.DialTimeout)*time.Second)
		defer cancel()
	}

	log.Info().NetIPAddrPort("remote_addr", raddr).Str("local_addr", laddr).Msg("tunnel handler connect local addr")
	lconn, err := h.LocalDialer.DialContext(ctx, "tcp", laddr)
	if err != nil {
		log.Error().Err(err).Msgf("Fail to dial %v", laddr)
		return
	}
	defer lconn.Close()

	go func() {
		defer rconn.Close()
		defer lconn.Close()
		_, err := io.Copy(rconn, lconn)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error().Err(err).NetAddr("src_addr", lconn.RemoteAddr()).NetAddr("dest_addr", rconn.RemoteAddr()).Msg("tunnel forwarding error")
		}
	}()

	_, err = io.Copy(lconn, rconn)
	if err != nil {
		log.Error().Err(err).NetAddr("src_addr", rconn.RemoteAddr()).NetAddr("dest_addr", lconn.RemoteAddr()).Msg("tunnel forwarding error")
	}
}

var _ net.Listener = (*SmuxSessionListener)(nil)

type SmuxSessionListener struct {
	Session *smux.Session
}

func (ln *SmuxSessionListener) Accept() (net.Conn, error) {
	return ln.Session.AcceptStream()
}

func (ln *SmuxSessionListener) Addr() net.Addr {
	return ln.Session.LocalAddr()
}

func (ln *SmuxSessionListener) RemoteAddr() net.Addr {
	return ln.Session.RemoteAddr()
}

func (ln *SmuxSessionListener) Close() error {
	return ln.Session.Close()
}

type TunnelListener struct {
	net.Listener
	closer io.Closer
	ctx    context.Context
}

func (ln *TunnelListener) Accept() (net.Conn, error) {
	if session, ok := ln.Listener.(*SmuxSessionListener); ok {
		log.Info().NetAddr("remote_addr", session.RemoteAddr()).Msg("smux session accept conn")
	}
	return ln.Listener.Accept()
}

func (ln *TunnelListener) Close() (err error) {
	if e := ln.Listener.Close(); e != nil {
		err = e
	}
	if e := ln.closer.Close(); e != nil {
		err = e
	}
	return
}

func (ln *TunnelListener) Done() <-chan struct{} {
	if ln.ctx == nil {
		return nil
	}
	return ln.ctx.Done()
}
