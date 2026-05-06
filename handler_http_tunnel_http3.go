package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/phuslu/log"
	"github.com/quic-go/quic-go"
)

func (h *HTTPTunnelHandler) serveHTTP3(rw http.ResponseWriter, req *http.Request, ri *HTTPRequestInfo, addrport netip.AddrPort, ln net.Listener) {
	qconn := ri.ClientConnOps.qc
	if qconn == nil {
		http.Error(rw, "http3 quic connection is unavailable", http.StatusBadRequest)
		return
	}

	if req.Header.Get("Sec-Websocket-Key") != "" {
		key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		rw.Header().Set("sec-websocket-accept", base64.StdEncoding.EncodeToString(key[:]))
	}
	rw.WriteHeader(http.StatusOK)
	http.NewResponseController(rw).Flush()

	exit := make(chan error, 2)
	ctx := req.Context()

	go func() {
		if ln == nil {
			return
		}
		for {
			rconn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					log.Error().Err(err).Msg("tunnel listener is closed")
					exit <- err
					return
				}
				log.Error().Err(err).Msg("failed to accept remote connection")
				time.Sleep(10 * time.Millisecond)
				if rconn != nil {
					rconn.Close()
				}
				continue
			}

			stream, err := qconn.OpenStreamSync(ctx)
			if err != nil {
				_ = rconn.Close()
				log.Error().Err(err).Msg("failed to open quic reverse stream")
				exit <- err
				return
			}
			if _, err := stream.Write([]byte{'L', 'Q', 1, 0}); err != nil {
				_ = rconn.Close()
				stream.CancelRead(0)
				_ = stream.Close()
				log.Error().Err(err).Msg("failed to write quic reverse stream open frame")
				exit <- err
				return
			}

			lconn := &QuicStreamConn{
				stream: stream,
				laddr:  qconn.LocalAddr(),
				raddr:  qconn.RemoteAddr(),
			}
			log.Info().NetAddr("remote_addr", rconn.RemoteAddr()).NetAddr("local_addr", qconn.RemoteAddr()).Int64("quic_stream_id", int64(stream.StreamID())).Msg("tunnel forwarding")

			go func() {
				defer rconn.Close()
				defer lconn.Close()
				go func() {
					defer rconn.Close()
					defer lconn.Close()
					_, err := io.Copy(rconn, lconn)
					if err != nil {
						log.Error().Err(err).NetAddr("src_addr", lconn.RemoteAddr()).NetAddr("dest_addr", rconn.RemoteAddr()).Msg("tunnel forwarding error")
					}
				}()
				_, err := io.Copy(lconn, rconn)
				if err != nil {
					log.Error().Err(err).NetAddr("src_addr", rconn.RemoteAddr()).NetAddr("dest_addr", lconn.RemoteAddr()).Msg("tunnel forwarding error")
				}
			}()
		}
	}()

	md := &MemoryDialer{
		Address:   addrport.String(),
		Session:   QuicMemorySession{conn: qconn},
		CreatedAt: time.Now().UnixNano(),
	}

	h.MemoryDialers.Store(addrport.String(), md)
	log.Info().Str("tunnel_listen", addrport.String()).NetAddr("remote_addr", qconn.RemoteAddr()).Msg("tunnel listen in memory")

	select {
	case err := <-exit:
		log.Info().Err(err).Msg("http3 quic reverse tunnel exit")
	case <-ctx.Done():
		log.Info().NetIPAddrPort("tunnel_listen", addrport).NetAddr("remote_addr", qconn.RemoteAddr()).Msg("http3 quic reverse tunnel request context done")
	case <-qconn.Context().Done():
		log.Info().NetIPAddrPort("tunnel_listen", addrport).NetAddr("remote_addr", qconn.RemoteAddr()).Msg("http3 quic reverse tunnel connection done")
	}

	if v, ok := h.MemoryDialers.Load(addrport.String()); ok && v.CreatedAt == md.CreatedAt {
		log.Info().Str("tunnel_listen", addrport.String()).NetAddr("remote_addr", qconn.RemoteAddr()).Msg("tunnel delete listener in memory")
		if v, ok := h.MemoryDialers.LoadAndDelete(addrport.String()); ok && v.CreatedAt != md.CreatedAt {
			log.Info().Str("tunnel_listen", addrport.String()).NetAddr("remote_addr", qconn.RemoteAddr()).Msg("tunnel return listener in memory")
			h.MemoryDialers.Store(addrport.String(), v)
		}
	}
}

type QuicMemorySession struct {
	conn *quic.Conn
}

func (s QuicMemorySession) Open(ctx context.Context) (net.Conn, error) {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write([]byte{'L', 'Q', 1, 0}); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, err
	}
	return &QuicStreamConn{
		stream: stream,
		laddr:  s.conn.LocalAddr(),
		raddr:  s.conn.RemoteAddr(),
	}, nil
}
