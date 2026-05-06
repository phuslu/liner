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
	"sync"
	"time"

	"github.com/phuslu/log"
	"github.com/quic-go/quic-go"
	"github.com/smallnest/ringbuffer"
)

var _ net.Conn = (*quicStreamConn)(nil)

type quicStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (c *quicStreamConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *quicStreamConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c *quicStreamConn) Close() error {
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *quicStreamConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *quicStreamConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

type quicMemorySession struct {
	conn *quic.Conn
}

func (s quicMemorySession) Open(ctx context.Context) (net.Conn, error) {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStreamConn{stream: stream, conn: s.conn}, nil
}

var _ net.Listener = (*QUICReverseListener)(nil)

type QUICReverseListener struct {
	conn  *quic.Conn
	body  io.ReadCloser
	pipe  *ringbuffer.PipeWriter
	ctx   context.Context
	stop  context.CancelFunc
	once  sync.Once
	laddr net.Addr
}

type multiCloser []io.Closer

func (cs multiCloser) Close() (err error) {
	for _, c := range cs {
		if c == nil {
			continue
		}
		err = errors.Join(err, c.Close())
	}
	return err
}

func NewQUICReverseListener(parent context.Context, conn *quic.Conn, body io.ReadCloser, pipe *ringbuffer.PipeWriter) *QUICReverseListener {
	ctx, stop := context.WithCancel(parent)
	ln := &QUICReverseListener{
		conn:  conn,
		body:  body,
		pipe:  pipe,
		ctx:   ctx,
		stop:  stop,
		laddr: conn.LocalAddr(),
	}
	go ln.watchControl()
	return ln
}

func (ln *QUICReverseListener) Accept() (net.Conn, error) {
	stream, err := ln.conn.AcceptStream(ln.ctx)
	if err != nil {
		return nil, err
	}
	log.Debug().NetAddr("remote_addr", ln.conn.RemoteAddr()).Int64("quic_stream_id", int64(stream.StreamID())).Msg("quic reverse stream accept conn")
	return &quicStreamConn{stream: stream, conn: ln.conn}, nil
}

func (ln *QUICReverseListener) Addr() net.Addr {
	return ln.laddr
}

func (ln *QUICReverseListener) Close() error {
	ln.close()
	return nil
}

func (ln *QUICReverseListener) Context() context.Context {
	return ln.ctx
}

func (ln *QUICReverseListener) watchControl() {
	if ln.body != nil {
		_, _ = io.Copy(io.Discard, ln.body)
	}
	ln.close()
}

func (ln *QUICReverseListener) close() {
	ln.once.Do(func() {
		ln.stop()
		if ln.body != nil {
			_ = ln.body.Close()
		}
		if ln.pipe != nil {
			_ = ln.pipe.Close()
		}
	})
}

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

			lconn := &quicStreamConn{stream: stream, conn: qconn}
			log.Info().NetAddr("remote_addr", rconn.RemoteAddr()).NetAddr("local_addr", qconn.RemoteAddr()).Int64("quic_stream_id", int64(stream.StreamID())).Msg("tunnel forwarding")

			go tunnelCopy(lconn, rconn)
		}
	}()

	md := &MemoryDialer{
		Address:   addrport.String(),
		Session:   quicMemorySession{conn: qconn},
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

func tunnelCopy(c1, c2 net.Conn) {
	defer c1.Close()
	defer c2.Close()
	go func() {
		defer c1.Close()
		defer c2.Close()
		_, err := io.Copy(c1, c2)
		if err != nil {
			log.Error().Err(err).NetAddr("src_addr", c2.RemoteAddr()).NetAddr("dest_addr", c1.RemoteAddr()).Msg("tunnel forwarding error")
		}
	}()
	_, err := io.Copy(c2, c1)
	if err != nil {
		log.Error().Err(err).NetAddr("src_addr", c1.RemoteAddr()).NetAddr("dest_addr", c2.RemoteAddr()).Msg("tunnel forwarding error")
	}
}
