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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/phuslu/log"
	"go4.org/netipx"
)

type HTTPTunnelHandler struct {
	Config        HTTPConfig
	TunnelLogger  log.Logger
	MemoryDialers *sync.Map // map[string]*MemoryDialer

	csvloader *FileLoader[[]UserInfo]
	listens   *netipx.IPSet
}

func (h *HTTPTunnelHandler) Load() error {
	if strings.HasSuffix(h.Config.Tunnel.AuthTable, ".csv") {
		h.csvloader = GetUserCsvLoader(h.Config.Tunnel.AuthTable)
		records := h.csvloader.Load()
		if records == nil {
			log.Fatal().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Tunnel.AuthTable).Msg("load auth_table failed")
		}
		log.Info().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Tunnel.AuthTable).Int("auth_table_size", len(*records)).Msg("load auth_table ok")
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
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	var user UserInfo
	if s := req.Header.Get("authorization"); s != "" {
		switch t, s, _ := strings.Cut(s, " "); t {
		case "Basic":
			if b, err := base64.StdEncoding.DecodeString(s); err == nil {
				user.Username, user.Password, _ = strings.Cut(string(b), ":")
			}
		}
	}

	if user.Username == "" || user.Password == "" {
		log.Error().Context(ri.LogContext).Str("username", user.Username).Msg("tunnel user authorization required")
		http.Error(rw, "Authorization Required", http.StatusUnauthorized)
		return
	}

	log.Info().Context(ri.LogContext).Str("username", user.Username).Str("password", user.Password).Msg("tunnel verify user")

	err := VerifyUserInfoByCsvLoader(h.csvloader, &user)
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel user auth failed")
		http.Error(rw, err.Error(), http.StatusUnauthorized)
		return
	}

	speedLimit := h.Config.Tunnel.SpeedLimit
	if s, _ := ri.ProxyUserInfo.Attrs["speed_limit"].(string); s != "" {
		n, _ := strconv.ParseInt(s, 10, 64)
		switch {
		case n > 0:
			speedLimit = n
		case n < 0:
			speedLimit = 0 // privileged users has no speed_limit
		}
	}

	if speedLimit > 0 {
		if ri.ClientTCPConn != nil {
			err := SetTcpMaxPacingRate(ri.ClientTCPConn, int(speedLimit))
			log.DefaultLogger.Err(err).Context(ri.LogContext).Int64("tunnel_speedlimit", speedLimit).Msg("set tunnel_speedlimit")
		} else {
			// TODO: speed limiter in user space
		}
	}

	allow, _ := user.Attrs["allow_tunnel"].(string)
	if allow == "0" {
		log.Error().Context(ri.LogContext).Str("username", user.Username).Str("allow_tunnel", allow).Msg("tunnel user permission denied")
		http.Error(rw, "permission denied", http.StatusForbidden)
		return
	}

	// req.URL.Path format is /.well-known/reverse/tcp/{listen_host}/{listen_port}/
	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	parts := strings.Split(req.URL.Path, "/")
	addr := net.JoinHostPort(parts[len(parts)-3], parts[len(parts)-2])

	if h.listens != nil && allow != "-1" {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel parse tcp listener error")
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		if !h.listens.Contains(ap.Addr()) {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel allow tcp listener error")
			http.Error(rw, "tunnel listen addr is not allow", http.StatusForbidden)
			return
		}
	}

	ln, err := (&net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Interval: 15 * time.Second,
			Count:    3,
		},
	}).Listen(req.Context(), "tcp", addr)
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open tcp listener error")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Context(ri.LogContext).Str("username", user.Username).Stringer("addr", ln.Addr()).Msg("tunnel open tcp listener")

	defer ln.Close()

	var conn net.Conn

	if req.ProtoAtLeast(2, 0) {
		raddr, err := net.ResolveTCPAddr("tcp", req.RemoteAddr)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Str("remote_addr", req.RemoteAddr).Msg("tunnel resolve remote addr error")
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
		laddr, err := net.ResolveTCPAddr("tcp", ri.ServerAddr)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Str("local_addr", ri.ServerAddr).Msg("tunnel resolve local addr error")
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
		conn = HTTPRequestStream{req.Body, rw, http.NewResponseController(rw), raddr, laddr}

		if req.Header.Get("Sec-Websocket-Key") != "" {
			key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			rw.Header().Set("sec-websocket-accept", base64.StdEncoding.EncodeToString(key[:]))
			rw.Header().Set("upgrade", "websocket")
			rw.Header().Set("connection", "Upgrade")
			rw.WriteHeader(http.StatusSwitchingProtocols)
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
			b = b.Str("HTTP/1.1 200 OK\r\n\r\n")
		}

		_, err = conn.Write(b)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel send response error")
			return
		}
	}

	session, err := yamux.Client(conn, &yamux.Config{
		AcceptBacklog:           256,
		PingBacklog:             32,
		EnableKeepAlive:         h.Config.Tunnel.EnableKeepAlive,
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
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open yamux session error")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	defer conn.Close()
	defer session.Close()

	exit := make(chan error, 2)

	go func(ctx context.Context) {
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

			lconn, err := session.Open(ctx)
			if err != nil {
				log.Error().Err(err).Msg("failed to open local session")
				exit <- err
				return
			}

			log.Info().Stringer("remote_addr", rconn.RemoteAddr()).Stringer("local_addr", conn.RemoteAddr()).Msg("tunnel forwarding")

			go func(c1, c2 net.Conn) {
				defer c1.Close()
				defer c2.Close()
				go func() {
					defer c1.Close()
					defer c2.Close()
					_, err := io.Copy(c1, c2)
					if err != nil {
						log.Error().Err(err).Stringer("src_addr", c2.RemoteAddr()).Stringer("dest_addr", c1.RemoteAddr()).Msg("tunnel forwarding error")
					}
				}()
				_, err := io.Copy(c2, c1)
				if err != nil {
					log.Error().Err(err).Stringer("src_addr", c1.RemoteAddr()).Stringer("dest_addr", c2.RemoteAddr()).Msg("tunnel forwarding error")
				}
			}(lconn, rconn)
		}
	}(req.Context())

	go func(ctx context.Context) {
		count := 0
		seconds := 5 + fastrandn(30)
		for {
			time.Sleep(time.Duration(seconds) * time.Second)
			rtt, err := session.Ping()
			switch {
			case count == 3:
				exit <- err
				return
			case err != nil:
				log.Error().Err(err).Str("tunnel_listen", ln.Addr().String()).Str("remote_addr", session.RemoteAddr().String()).Msg("tunnel ping error")
				count++
				seconds = 1 + fastrandn(5)
			default:
				log.Trace().Str("tunnel_listen", ln.Addr().String()).Str("remote_addr", session.RemoteAddr().String()).Dur("ping_ms", rtt).Msg("tunnel ping successfully")
				count = 0
				seconds = 5 + fastrandn(30)
			}
		}
	}(req.Context())

	h.MemoryDialers.Store(addr, &MemoryDialer{Session: session, Address: addr})
	err = <-exit
	h.MemoryDialers.Delete(addr)

	log.Info().Err(err).Msg("tunnel forwarding exit.")
}
