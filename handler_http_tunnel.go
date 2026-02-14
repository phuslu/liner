package main

import (
	"cmp"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/phuslu/log"
	"github.com/xtaci/smux"
	"go4.org/netipx"
)

type HTTPTunnelHandler struct {
	Config        HTTPConfig
	TunnelLogger  log.Logger
	MemoryDialers *MemoryDialers

	userchecker AuthUserChecker
	listens     *netipx.IPSet
}

func (h *HTTPTunnelHandler) Load() error {
	if table := h.Config.Tunnel.AuthTable; table != "" {
		loader := NewAuthUserLoaderFromTable(table)
		records, err := loader.LoadAuthUsers(context.Background())
		if err != nil {
			log.Fatal().Err(err).Strs("server_name", h.Config.ServerName).Str("auth_table", table).Msg("load auth_table failed")
		}
		log.Info().Strs("server_name", h.Config.ServerName).Str("auth_table", table).Int("auth_table_size", len(records)).Msg("load auth_table ok")
		h.userchecker = &AuthUserLoadChecker{loader}
	}

	if len(h.Config.Tunnel.AllowListens) > 0 {
		var builder netipx.IPSetBuilder
		for _, listen := range h.Config.Tunnel.AllowListens {
			switch {
			case strings.Count(listen, "-") == 1:
				if iprange, err := netipx.ParseIPRange(listen); err == nil {
					builder.AddRange(iprange)
				}
			case strings.Contains(listen, "/"):
				if prefix, err := netip.ParsePrefix(listen); err == nil {
					builder.AddPrefix(prefix)
				}
			default:
				if ip, err := netip.ParseAddr(listen); err == nil {
					builder.Add(ip)
				}
			}
		}
		ipset, err := builder.IPSet()
		if err != nil {
			return err
		}
		h.listens = ipset
	}

	return nil
}

func (h *HTTPTunnelHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(HTTPRequestInfoContextKey).(*HTTPRequestInfo)

	user := ri.AuthUserInfo

	if user.Username == "" || user.Password == "" || h.userchecker == nil {
		log.Error().Context(ri.LogContext).Str("username", user.Username).Msg("tunnel user authorization required")
		http.Error(rw, "Authorization Required", http.StatusUnauthorized)
		return
	}

	log.Info().Context(ri.LogContext).Str("username", user.Username).Str("password", user.Password).Msg("tunnel verify user")

	err := h.userchecker.CheckAuthUser(req.Context(), &user)
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel user auth failed")
		http.Error(rw, err.Error(), http.StatusUnauthorized)
		return
	}

	speedLimit := h.Config.Tunnel.SpeedLimit
	if s := ri.ProxyUserInfo.Attrs["speed_limit"]; s != "" {
		n, _ := strconv.ParseInt(s, 10, 64)
		switch {
		case n > 0:
			speedLimit = n
		case n < 0:
			speedLimit = 0 // privileged users has no speed_limit
		}
	}

	if speedLimit > 0 {
		if ri.ClientConnOps.SupportTCP() {
			err := ri.ClientConnOps.SetTcpMaxPacingRate(int(speedLimit))
			log.DefaultLogger.Err(err).Context(ri.LogContext).Int64("tunnel_speedlimit", speedLimit).Msg("set tunnel_speedlimit")
		} else {
			// TODO: speed limiter in user space
		}
	}

	allow := user.Attrs["allow_tunnel"]
	if allow == "0" {
		log.Error().Context(ri.LogContext).Str("username", user.Username).Str("allow_tunnel", allow).Msg("tunnel user permission denied")
		http.Error(rw, "permission denied", http.StatusForbidden)
		return
	}

	// req.URL.Path format is /.well-known/reverse/tcp/{listen_host}/{listen_port}/
	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	parts := strings.Split(req.URL.Path, "/")
	addrport, err := netip.ParseAddrPort(net.JoinHostPort(parts[len(parts)-3], parts[len(parts)-2]))
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel parse tcp listener error")
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	if h.listens != nil && allow != "-1" {
		if !h.listens.Contains(addrport.Addr()) {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel allow tcp listener error")
			http.Error(rw, "tunnel listen addr is not allow", http.StatusForbidden)
			return
		}
	}

	var ln net.Listener

	if MemoryDialerIPPrefix.Contains(addrport.Addr()) {
		if _, ok := h.MemoryDialers.Load(addrport.String()); ok && allow != "-1" {
			err := errors.New("bind address " + addrport.String() + " is inuse")
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open memory listener error")
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		ln, err = (&net.ListenConfig{
			KeepAliveConfig: net.KeepAliveConfig{
				Enable:   true,
				Interval: 15 * time.Second,
				Count:    3,
			},
		}).Listen(req.Context(), "tcp", addrport.String())
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open tcp listener error")
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Info().Context(ri.LogContext).Str("username", user.Username).NetAddr("addr", ln.Addr()).Msg("tunnel open tcp listener")

		defer ln.Close()
	}

	var conn net.Conn

	if req.ProtoAtLeast(2, 0) {
		conn = HTTPRequestStream{req.Body, rw, http.NewResponseController(rw), net.TCPAddrFromAddrPort(ri.RemoteAddr), net.TCPAddrFromAddrPort(ri.ServerAddr)}

		if req.Header.Get("Sec-Websocket-Key") != "" {
			key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			rw.Header().Set("sec-websocket-accept", base64.StdEncoding.EncodeToString(key[:]))
			if req.ProtoMajor == 2 {
				rw.Header().Set("upgrade", "websocket")
				rw.Header().Set("connection", "Upgrade")
				rw.WriteHeader(http.StatusSwitchingProtocols)
			} else {
				rw.WriteHeader(http.StatusOK)
			}
		} else {
			rw.WriteHeader(http.StatusOK)
		}
		http.NewResponseController(rw).Flush()
	} else {
		conn, _, err = http.NewResponseController(rw).Hijack()
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel hijack request error")
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
		b := AppendableBytes(make([]byte, 0, 2048))
		switch req.Header.Get("Connection") {
		case "upgrade", "Upgrade":
			b = b.Str("HTTP/1.1 101 Switching Protocols\r\n")
			switch req.Header.Get("Upgrade") {
			case "websocket":
				wskey := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				b = b.Str("sec-websocket-accept: ").Base64(wskey[:]).Str("\r\n")
				b = b.Str("connection: Upgrade\r\n")
				b = b.Str("upgrade: websocket\r\n")
			case "reverse":
				b = b.Str("connection: Upgrade\r\n")
				b = b.Str("upgrade: reverse\r\n")
			}
			b = b.Str("\r\n")
		default:
			b = b.Str("HTTP/1.1 200 Connection Established\r\n\r\n")
		}

		_, err = conn.Write(b)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel send response error")
			return
		}
	}

	conn = &AutoCloseConn{
		Conn:    conn,
		CloseAt: time.Now().Add(time.Duration(72000+fastrandn(14400)) * time.Second),
	}

	session, err := func() (*MuxSession, error) {
		switch {
		case strings.Contains(req.UserAgent(), " yamux/"):
			client, err := yamux.Client(conn, &yamux.Config{
				AcceptBacklog:           256,
				PingBacklog:             32,
				EnableKeepAlive:         true,
				KeepAliveInterval:       30 * time.Second,
				MeasureRTTInterval:      30 * time.Second,
				ConnectionWriteTimeout:  10 * time.Second,
				MaxIncomingStreams:      1000,
				InitialStreamWindowSize: 256 * 1024,
				MaxStreamWindowSize:     16 * 1024 * 1024,
				LogOutput:               SlogWriter{Logger: log.DefaultLogger.Slog()},
				ReadBufSize:             4096,
				MaxMessageSize:          64 * 1024,
				WriteCoalesceDelay:      100 * time.Microsecond,
			}, nil)
			if err != nil {
				return nil, err
			}
			return &MuxSession{YamuxSession: client}, nil
		default:
			client, err := smux.Client(conn, &smux.Config{
				Version:           1,
				KeepAliveInterval: 10 * time.Second,
				KeepAliveTimeout:  30 * time.Second,
				MaxFrameSize:      32768,
				MaxReceiveBuffer:  4194304,
				MaxStreamBuffer:   65536,
			})
			if err != nil {
				return nil, err
			}
			return &MuxSession{SmuxSession: client}, nil
		}
	}()
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open mux session error")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	defer conn.Close()
	defer session.Close()

	exit := make(chan error, 2)

	go func(ctx context.Context) {
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
				rconn.Close()
				continue
			}

			lconn, err := session.OpenConn(ctx)
			if err != nil {
				log.Error().Err(err).Msg("failed to open local session")
				exit <- err
				return
			}

			log.Info().NetAddr("remote_addr", rconn.RemoteAddr()).NetAddr("local_addr", conn.RemoteAddr()).Msg("tunnel forwarding")

			go func(c1, c2 net.Conn) {
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
			}(lconn, rconn)
		}
	}(req.Context())

	go func(ctx context.Context) {
		count := 0
		seconds := 5 + fastrandn(30)
		for {
			time.Sleep(time.Duration(seconds) * time.Second)
			rtt, err := session.Ping(ctx)
			switch {
			case count == 3:
				exit <- err
				return
			case errors.Is(err, errors.ErrUnsupported):
				seconds = 5 + fastrandn(30)
			case err != nil:
				log.Error().Err(err).NetIPAddrPort("tunnel_listen", addrport).NetAddr("remote_addr", session.RemoteAddr()).Msg("tunnel ping error")
				count++
				seconds = 1 + fastrandn(5)
			default:
				log.Trace().NetIPAddrPort("tunnel_listen", addrport).NetAddr("remote_addr", session.RemoteAddr()).Dur("ping_ms", rtt).Msg("tunnel ping successfully")
				count = 0
				seconds = 5 + fastrandn(30)
			}
		}
	}(req.Context())

	md := &MemoryDialer{
		Address:   addrport.String(),
		Session:   session,
		CreatedAt: time.Now().UnixNano(),
	}

	h.MemoryDialers.Store(addrport.String(), md)
	log.Info().Str("tunnel_listen", addrport.String()).NetAddr("remote_addr", session.RemoteAddr()).Msg("tunnel listen in memory")

	err = <-exit

	if v, ok := h.MemoryDialers.Load(addrport.String()); ok && v.CreatedAt == md.CreatedAt {
		log.Info().Str("tunnel_listen", addrport.String()).NetAddr("remote_addr", session.RemoteAddr()).Msg("tunnel delete listener in memory")
		if v, ok := h.MemoryDialers.LoadAndDelete(addrport.String()); ok && v.CreatedAt != md.CreatedAt {
			log.Info().Str("tunnel_listen", addrport.String()).NetAddr("remote_addr", session.RemoteAddr()).Msg("tunnel return listener in memory")
			h.MemoryDialers.Store(addrport.String(), v)
		}
	}

	log.Info().Err(err).Msg("tunnel forwarding exit.")
}

type AutoCloseConn struct {
	net.Conn
	CloseAt time.Time
}

func (c *AutoCloseConn) Read(b []byte) (n int, err error) {
	if time.Since(c.CloseAt) > 0 {
		return 0, cmp.Or(c.Conn.Close(), net.ErrClosed)
	}
	return c.Conn.Read(b)
}

func (c *AutoCloseConn) Write(b []byte) (n int, err error) {
	if time.Since(c.CloseAt) > 0 {
		return 0, cmp.Or(c.Conn.Close(), net.ErrClosed)
	}
	return c.Conn.Write(b)
}
