package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/libp2p/go-yamux/v5"
	"github.com/phuslu/log"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"github.com/smallnest/ringbuffer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http2"
)

var TunnelUserAgent = "Liner/" + version + " (" + runtime.GOOS + "; " + runtime.GOARCH + "; " + runtime.Version() + ") yamux/v5 quic-go/v0"

type TunnelHandler struct {
	Config          TunnelConfig
	MemoryListeners *xsync.Map[string, *MemoryListener]
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
		dialerURL := h.Dialers[h.Config.Dialer]

		var ln net.Listener
		var err error
		switch strings.Split(dialerURL, "://")[0] {
		case "ssh", "ssh2":
			ln, err = h.sshtunnel(ctx, h.Config.Dialer, dialerURL)
		case "http", "https", "ws", "wss":
			ln, err = h.h1tunnel(ctx, h.Config.Dialer, dialerURL)
		case "http2":
			ln, err = h.h2tunnel(ctx, h.Config.Dialer, dialerURL)
		case "http3", "quic":
			ln, err = h.h3tunnel(ctx, h.Config.Dialer, dialerURL)
		default:
			log.Fatal().Str("dialer_url", dialerURL).Msg("dialer tunnel is unsupported")
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
		if ml, ok := h.MemoryListeners.Load(h.Config.ProxyPass); ok && ml != nil {
			log.Info().NetAddr("remote_host", rconn.RemoteAddr()).NetAddr("local_addr", ml.Addr()).Msg("tunnel handler memory listener local addr")
			ml.SendConn(rconn)
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

type TunnelListener struct {
	net.Listener
	closer io.Closer
	ctx    context.Context
}

func (ln *TunnelListener) Accept() (net.Conn, error) {
	if session, ok := ln.Listener.(*YamuxSessionListener); ok {
		log.Debug().NetAddr("remote_addr", session.RemoteAddr()).Msg("mux session accept conn")
	}
	return ln.Listener.Accept()
}

func (ln *TunnelListener) Close() (err error) {
	if ln.Listener != nil {
		if e := ln.Listener.Close(); e != nil {
			err = e
		}
	}
	if ln.closer != nil {
		if e := ln.closer.Close(); e != nil {
			err = e
		}
	}
	return
}

func (ln *TunnelListener) Done() <-chan struct{} {
	if ln.ctx == nil {
		return nil
	}
	return ln.ctx.Done()
}

func (h *TunnelHandler) sshtunnel(ctx context.Context, dialerName, dialerURL string) (net.Listener, error) {
	log.Info().Str("dialer_name", dialerName).Msg("connecting tunnel host")

	u, err := url.Parse(dialerURL)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer %s: %s", dialerName, dialerURL)
	}

	if IsMemoryAddress(h.Config.RemoteListen[0]) {
		return nil, fmt.Errorf("invalid remote_listen memory address in ssh tunnel: %s", h.Config.RemoteListen[0])
	}

	config := &ssh.ClientConfig{
		User: u.User.Username(),
		Auth: []ssh.AuthMethod{
			ssh.Password(first(u.User.Password())),
		},
		ClientVersion:   TunnelUserAgent,
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
	ln, err := client.Listen("tcp", h.Config.RemoteListen[0])
	if err != nil {
		log.Error().Err(err).Msgf("failed to remote listen %s", h.Config.RemoteListen[0])
		client.Close()
		return nil, fmt.Errorf("failed to dial remote %s: %w", h.Config.RemoteListen[0], err)
	}

	if tc, _ := conn.(*net.TCPConn); conn != nil && h.Config.SpeedLimit > 0 {
		err := (ConnOps{tc, nil}).SetTcpMaxPacingRate(int(h.Config.SpeedLimit))
		log.DefaultLogger.Err(err).Str("tunnel_proxy_pass", h.Config.ProxyPass).Str("tunnel_dialer_name", h.Config.Dialer).Int64("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set speedlimit")
	}

	return &TunnelListener{
		Listener: ln,
		closer:   client,
		ctx:      nil,
	}, nil
}

func (h *TunnelHandler) h1tunnel(ctx context.Context, dialerName, dialerURL string) (net.Listener, error) {
	log.Info().Str("dialer_name", dialerName).Msg("connecting tunnel host")

	ctx, cancel := context.WithTimeout(ctx, time.Duration(cmp.Or(h.Config.DialTimeout, 10))*time.Second)
	defer cancel()

	u, err := url.Parse(dialerURL)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer %s: %s", dialerName, dialerURL)
	}

	host, port, ech := u.Hostname(), u.Port(), []byte{}
	if u.Query().Get("ech") == "true" {
		https, err := h.DnsResolver.Client.LookupHTTPS(ctx, host)
		log.Debug().Str("dns_server", h.DnsResolver.Client.Addr).Interface("https", https).AnErr("error", err).Msg("lookup https records")
		if len(https) == 0 && err == nil {
			err = fmt.Errorf("lookup https %v error: emtpy record", host)
		}
		if err != nil {
			log.Error().Err(err).Str("tunnel_host", host).Str("tunnel_url", u.String()).Msg("lookup https error")
			return nil, err
		}
		if len(https[0].ECH) > 0 {
			ech = https[0].ECH
		}
		switch {
		case len(https[0].IPv4Hint) > 0:
			host = https[0].IPv4Hint[0].String()
		case len(https[0].IPv6Hint) > 0:
			host = https[0].IPv6Hint[0].String()
		}
	}
	if resolve := u.Query().Get("resolve"); resolve != "" {
		host = resolve
	}
	if _, err := netip.ParseAddr(host); err != nil {
		ips, err := h.DnsResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		host = ips[0].String()
	}
	if port == "" {
		switch u.Scheme {
		case "http,", "ws":
			port = "80"
		default:
			port = "443"
		}
	}

	hostport := net.JoinHostPort(host, port)

	log.Info().Str("dialer_name", dialerName).Str("hostport", hostport).Msg("connecting tunnel hostport")
	conn, err := h.LocalDialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		log.Error().Err(err).Str("tunnel_host", hostport).Msg("connect tunnel host error")
		return nil, err
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		config := net.KeepAliveConfig{
			Enable:   true,
			Idle:     15 * time.Second,
			Interval: 15 * time.Second,
			Count:    3,
		}
		err := tc.SetKeepAliveConfig(config)
		log.DefaultLogger.Err(err).Str("tunnel_host", hostport).Any("keepalive_config", config).Msg("set tunnel host keepalive")
		if rate, _ := strconv.ParseUint(u.Query().Get("brutal_rate"), 10, 64); rate > 0 {
			err := (ConnOps{tc, nil}).SetTcpCongestion("brutal", uint64(rate), uint32(20))
			log.DefaultLogger.Err(err).Str("tunnel_host", hostport).Uint64("tunnel_brutal_rate", rate).Msg("set tunnel brutal rate")
		} else if h.Config.SpeedLimit > 0 {
			err := (ConnOps{tc, nil}).SetTcpMaxPacingRate(int(h.Config.SpeedLimit))
			log.DefaultLogger.Err(err).Str("tunnel_host", hostport).Any("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set tunnel speedlimit")
		}
	}

	switch u.Scheme {
	case "https", "wss":
		tlsConfig := &tls.Config{
			NextProtos:         []string{"http/1.1"},
			InsecureSkipVerify: u.Query().Get("insecure") == "true",
			ServerName:         u.Hostname(),
		}
		if len(ech) > 0 {
			tlsConfig.MinVersion = tls.VersionTLS13
			tlsConfig.EncryptedClientHelloConfigList = ech
		}
		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			_ = conn.Close()
			log.Error().Err(err).Str("tunnel_host", hostport).Msg("handshake tunnel host error")
			return nil, err
		}
		conn = tlsConn
	}

	targetHost, targetPort, err := net.SplitHostPort(h.Config.RemoteListen[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote_listen addr: %s", h.Config.RemoteListen[0])
	}

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	buf := AppendableBytes(make([]byte, 0, 2048))
	buf = buf.Str("GET ").Str(HTTPWellknownBase64PathPrefix).Base64(s2b(HTTPTunnelReverseTCPPathPrefix + targetHost + "/" + targetPort + "/")).Str(" HTTP/1.1\r\n")
	buf = buf.Str("Host: ").Str(u.Hostname()).Str("\r\n")
	buf = buf.Str("Authorization: Basic ").Base64(AppendableBytes(make([]byte, 0, 128)).Str(u.User.Username()).Byte(':').Str(first(u.User.Password()))).Str("\r\n")
	buf = buf.Str("User-Agent: ").Str(TunnelUserAgent).Str("\r\n")
	switch u.Scheme {
	case "ws", "wss":
		buf = buf.Str("Connection: Upgrade\r\n")
		buf = buf.Str("Upgrade: websocket\r\n")
		buf = buf.Str("Sec-WebSocket-Version: 13\r\n")
		buf = buf.Str("Sec-WebSocket-Key: ").Base64(strconv.AppendUint(make([]byte, 0, 64), uint64(fastrandn(1<<32-1)), 10)).Str("\r\n")
	default:
		buf = buf.Str("Connection: Upgrade\r\n")
		buf = buf.Str("Upgrade: reverse\r\n")
	}
	buf = buf.Str("\r\n")

	log.Info().NetAddr("tunnel_conn_addr", conn.RemoteAddr()).Bytes("request_body", buf).Msg("send tunnel request")

	conn.SetDeadline(time.Now().Add(time.Duration(cmp.Or(h.Config.DialTimeout, 10)) * time.Second))
	defer conn.SetDeadline(time.Time{})

	_, err = conn.Write(buf)
	if err != nil {
		return nil, err
	}

	// see https://github.com/golang/go/issues/5373
	buf = buf[:cap(buf)]
	for i := range buf {
		buf[i] = 0
	}

	b := buf
	total := 0

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		total += n
		buf = buf[n:]

		if i := bytes.Index(b, CRLFCRLF); i > 0 {
			if i+4 < total {
				conn = &ConnWithData{conn, b[i+4 : total]}
			}
			break
		}
	}

	status := 0
	n := bytes.IndexByte(b, ' ')
	if n < 0 {
		return nil, fmt.Errorf("tunnel: failed to tunnel remote %s via %s: %s", h.Config.RemoteListen[0], conn.RemoteAddr().String(), bytes.TrimRight(b, "\x00"))
	}
	for i, c := range b[n+1:] {
		if i == 3 || c < '0' || c > '9' {
			break
		}
		status = status*10 + int(c-'0')
	}
	if status != http.StatusOK && status != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("tunnel: failed to tunnel remote %s via %s: %s", h.Config.RemoteListen[0], conn.RemoteAddr().String(), bytes.TrimRight(b, "\x00"))
	}

	if !h.Config.DisableKeepalive {
		conn = &IdleTimeoutConn{
			Conn:        conn,
			IdleTimeout: 3600 * time.Second,
		}
	}

	session, err := yamux.Server(conn, &yamux.Config{
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
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel: open mux server on remote %s: %w", h.Config.RemoteListen[0], err)
	}

	return &TunnelListener{
		Listener: &YamuxSessionListener{session},
		closer:   conn,
		ctx:      nil,
	}, nil
}

func (h *TunnelHandler) h2tunnel(ctx context.Context, dialerName, dialerURL string) (net.Listener, error) {
	log.Info().Str("dialer_name", dialerName).Msg("connecting tunnel host")

	u, err := url.Parse(dialerURL)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer %s: %s", dialerName, dialerURL)
	}

	transport := &http2.Transport{
		MaxReadFrameSize:   1024 * 1024, // 1MB read frame, https://github.com/golang/go/issues/47840
		DisableCompression: false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			hostport := net.JoinHostPort(cmp.Or(u.Query().Get("resolve"), u.Hostname()), cmp.Or(u.Port(), "443"))
			dialer := h.LocalDialer
			if md := MemoryDialerOf(ctx, network, hostport); md != nil {
				dialer = md
			}
			if dialer == nil {
				dialer = &net.Dialer{}
			}
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", hostport)
			if err != nil {
				return nil, err
			}

			if tc, _ := conn.(*net.TCPConn); conn != nil {
				if rate, _ := strconv.ParseUint(u.Query().Get("brutal_rate"), 10, 64); rate > 0 {
					err := (ConnOps{tc, nil}).SetTcpCongestion("brutal", uint64(rate), uint32(20))
					log.DefaultLogger.Err(err).Str("tunnel_proxy_pass", h.Config.ProxyPass).Str("tunnel_dialer_name", h.Config.Dialer).Uint64("tunnel_brutal_rate", rate).Msg("set tunnel brutal rate")
				} else if h.Config.SpeedLimit > 0 {
					err := (ConnOps{tc, nil}).SetTcpMaxPacingRate(int(h.Config.SpeedLimit))
					log.DefaultLogger.Err(err).Str("tunnel_proxy_pass", h.Config.ProxyPass).Str("tunnel_dialer_name", h.Config.Dialer).Int64("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set tunnel speedlimit")
				}
			}

			tlsConfig := &utls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				InsecureSkipVerify: u.Query().Get("insecure") == "true",
				ServerName:         u.Hostname(),
			}

			tlsConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)

			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				return nil, err
			}

			return tlsConn, nil
		},
	}

	targetHost, targetPort, err := net.SplitHostPort(h.Config.RemoteListen[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote_listen addr: %s", h.Config.RemoteListen[0])
	}

	pr, pw := ringbuffer.New(8192).Pipe()

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+u.Host+HTTPTunnelReverseTCPPathPrefix+targetHost+"/"+targetPort+"/", pr)
	if err != nil {
		return nil, err
	}
	req.ContentLength = -1
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("content-type", "application/octet-stream")
	req.Header.Set("user-agent", TunnelUserAgent)
	if u.User != nil {
		req.Header.Set("authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+first(u.User.Password()))))
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		log.Debug().Any("dialer_http_header", header).Msg("http2 dialer set extras headers")
		for key, values := range header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	var remoteAddr, localAddr net.Addr
	var netConn net.Conn

	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
			netConn = connInfo.Conn
		},
	}))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	log.Debug().Int("resp_statuscode", resp.StatusCode).Any("resp_header", resp.Header).Msg("http2 dialer websocket response")

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("proxy: read from " + u.Host + " error: " + resp.Status + ": " + string(data))
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.TCPAddr{}, &net.TCPAddr{}
	}

	conn := &http2Stream{
		body: resp.Body,
		pipe: pw,
		conn: netConn,
		closeRead: func(error) error {
			return resp.Body.Close()
		},
		closeWrite: func(err error) error {
			if err != nil {
				return pw.CloseWithError(err)
			}
			return pw.Close()
		},
		cancel: nil,
	}

	session, err := yamux.Server(conn, &yamux.Config{
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
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel: open mux server on remote %s: %w", h.Config.RemoteListen[0], err)
	}

	return &TunnelListener{
		Listener: &YamuxSessionListener{session},
		closer:   conn,
		ctx:      nil,
	}, nil
}

func (h *TunnelHandler) h3tunnel(ctx context.Context, dialerName, dialerURL string) (net.Listener, error) {
	log.Info().Str("dialer_name", dialerName).Msg("connecting tunnel host")

	u, err := url.Parse(dialerURL)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer %s: %s", dialerName, dialerURL)
	}

	transport := &http3.Transport{
		DisableCompression: false,
		EnableDatagrams:    true,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, err := quic.DialAddrEarly(ctx,
				net.JoinHostPort(cmp.Or(u.Query().Get("resolve"), u.Hostname()), cmp.Or(u.Port(), "443")),
				&tls.Config{
					NextProtos:         []string{"h3"},
					InsecureSkipVerify: u.Query().Get("insecure") == "true",
					ServerName:         u.Hostname(),
				},
				&quic.Config{
					DisablePathMTUDiscovery:    false,
					EnableDatagrams:            true,
					MaxIdleTimeout:             45 * time.Second,
					MaxIncomingUniStreams:      200,
					MaxIncomingStreams:         200,
					MaxStreamReceiveWindow:     6 * 1024 * 1024,
					MaxConnectionReceiveWindow: 100 * 1024 * 1024,
				},
			)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}

	targetHost, targetPort, err := net.SplitHostPort(h.Config.RemoteListen[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote_listen addr: %s", h.Config.RemoteListen[0])
	}

	pr, pw := ringbuffer.New(8192).Pipe()

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+u.Host, pr)
	if err != nil {
		return nil, err
	}
	req.ContentLength = -1
	req.Header.Set("location", HTTPTunnelReverseTCPPathPrefix+targetHost+"/"+targetPort+"/")
	req.Header.Set("content-type", "application/octet-stream")
	req.Header.Set("user-agent", TunnelUserAgent)
	if u.User != nil {
		req.Header.Set("authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+first(u.User.Password()))))
	}
	if u.Query().Get("websocket") == "true" {
		req.Method = http.MethodConnect
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", string(strconv.AppendUint(make([]byte, 0, 64), uint64(fastrandn(1<<32-1)), 10)))
	} else {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "reverse")
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		log.Debug().Any("dialer_http_header", header).Msg("http3 dialer set extras headers")
		for key, values := range header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	var remoteAddr, localAddr net.Addr
	var quicConn *quic.Conn

	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
			// see https://github.com/quic-go/quic-go/blob/master/http3/trace.go
			if data := (*[2]unsafe.Pointer)(unsafe.Pointer(&connInfo.Conn))[1]; data != nil {
				type fakeConn struct{ conn *quic.Conn }
				quicConn = (*fakeConn)(data).conn
			}
		},
	}))

	resp, err := transport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: false})
	if err != nil {
		if errmsg := err.Error(); strings.Contains(errmsg, "timeout: ") || strings.Contains(errmsg, "context deadline exceeded") || strings.Contains(errmsg, "context canceled") {
			log.Warn().Err(err).Msg("close underlying http3 connection")
		}
		transport.Close()
		return nil, err
	}

	log.Debug().Int("resp_statuscode", resp.StatusCode).Any("resp_header", resp.Header).Msg("http3dialer websocket response")

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("proxy: read from " + u.Host + " error: " + resp.Status + ": " + string(data))
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.UDPAddr{}, &net.UDPAddr{}
	}

	ln := NewQUICReverseListener(ctx, quicConn, resp.Body, pw)
	return &TunnelListener{
		Listener: ln,
		closer:   transport,
		ctx:      quicConn.Context(),
	}, nil
}

var _ net.Listener = (*YamuxSessionListener)(nil)

type YamuxSessionListener struct {
	session *yamux.Session
}

func (ln *YamuxSessionListener) Accept() (net.Conn, error) {
	return ln.session.AcceptStream()
}

func (ln *YamuxSessionListener) Addr() net.Addr {
	return ln.session.LocalAddr()
}

func (ln *YamuxSessionListener) RemoteAddr() net.Addr {
	return ln.session.RemoteAddr()
}

func (ln *YamuxSessionListener) Close() error {
	return ln.session.Close()
}

var _ net.Listener = (*QUICReverseListener)(nil)

type QUICReverseListener struct {
	conn *quic.Conn
	body io.ReadCloser
	pipe *ringbuffer.PipeWriter
	ctx  context.Context
	stop context.CancelFunc
	once sync.Once
}

func NewQUICReverseListener(parent context.Context, conn *quic.Conn, body io.ReadCloser, pipe *ringbuffer.PipeWriter) *QUICReverseListener {
	ctx, stop := context.WithCancel(parent)
	ln := &QUICReverseListener{
		conn: conn,
		body: body,
		pipe: pipe,
		ctx:  ctx,
		stop: stop,
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
	return &QuicStreamConn{
		stream: stream,
		laddr:  ln.conn.LocalAddr(),
		raddr:  ln.conn.RemoteAddr(),
	}, nil
}

func (ln *QUICReverseListener) Addr() net.Addr {
	return ln.conn.LocalAddr()
}

func (ln *QUICReverseListener) Close() error {
	ln.close()
	return nil
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
