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
)

type TunnelHandler struct {
	Config          TunnelConfig
	MemoryListeners *sync.Map // map[string]*MemoryListener
	Resolver        *Resolver
	LocalDialer     Dialer
	Dialers         map[string]string
}

func (h *TunnelHandler) Load() error {
	if len(h.Config.Listen) != 1 {
		return fmt.Errorf("invalid tunnel listen: %v", h.Config.Listen)
	}
	return nil
}

func (h *TunnelHandler) Serve(ctx context.Context) {
	loop := func() bool {
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
			log.Error().Err(err).Msgf("Failed to listen %s", h.Config.Listen[0])
			time.Sleep(2 * time.Second)
			return true
		}

		defer ln.Close()

		log.Info().Msgf("Listening on remote %s", h.Config.Listen[0])

		// Accept connections from the remote side
		for {
			rconn, err := ln.Accept()
			if err != nil || rconn == nil || reflect.ValueOf(rconn).IsNil() {
				log.Error().Err(err).Any("rconn", rconn).Msg("Failed to accept remote connection")
				time.Sleep(10 * time.Millisecond)
				ln.Close()
				return true
			}

			go h.handle(ctx, rconn, h.Config.ProxyPass)
		}
	}

	for loop() {
		delay := time.Duration(5+log.Fastrandn(10)) * time.Second
		log.Info().Stringer("delay", delay).Msg("tunnel loop...")
		time.Sleep(delay)
	}

	return
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

	rhost, _, _ := net.SplitHostPort(rconn.RemoteAddr().String())
	ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For": []string{rhost},
	})

	if h.Config.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.DialTimeout)*time.Second)
		defer cancel()
	}

	log.Info().Str("remote_host", rhost).Str("local_addr", laddr).Msg("tunnel handler connect local addr")
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

type TunnelListener struct {
	net.Listener
	Closer io.Closer
}

func (ln *TunnelListener) Close() (err error) {
	if e := ln.Listener.Close(); e != nil {
		err = e
	}
	if e := ln.Closer.Close(); e != nil {
		err = e
	}
	return
}
