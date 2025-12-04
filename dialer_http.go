package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"
)

var _ Dialer = (*HTTPDialer)(nil)

type HTTPDialer struct {
	Username   string
	Password   string
	Host       string
	Port       string
	TLS        bool
	PSK        string
	Websocket  bool
	Insecure   bool
	ECH        bool
	UserAgent  string
	CACert     string
	ClientKey  string
	ClientCert string
	Resolve    map[string]string
	Dialer     Dialer
	Logger     *slog.Logger
	Resolver   *Resolver

	mu        sync.Mutex
	tlsConfig *tls.Config
}

func (d *HTTPDialer) init() error {
	if !d.TLS || d.tlsConfig != nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.tlsConfig = &tls.Config{
		InsecureSkipVerify: d.Insecure,
		ServerName:         d.Host,
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}
	if d.CACert != "" && d.ClientKey != "" && d.ClientCert != "" {
		caData, err := os.ReadFile(d.CACert)
		if err != nil {
			return err
		}

		cert, err := tls.LoadX509KeyPair(d.ClientCert, d.ClientKey)
		if err != nil {
			return err
		}

		d.tlsConfig.RootCAs = x509.NewCertPool()
		d.tlsConfig.RootCAs.AppendCertsFromPEM(caData)
		d.tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return nil
}

var CRLFCRLF = []byte{'\r', '\n', '\r', '\n'}

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := d.init(); err != nil {
		return nil, err
	}

	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("httpdialer: no support for HTTP proxy connections of type " + network)
	}

	hostport := net.JoinHostPort(d.Host, d.Port)
	for _, key := range []string{hostport, d.Host} {
		if value, _ := d.Resolve[key]; value != "" {
			hostport = net.JoinHostPort(value, d.Port)
			break
		}
	}

	dialer := d.Dialer
	if m, ok := ctx.Value(DialerMemoryDialersContextKey).(*sync.Map); ok && m != nil {
		if v, ok := m.Load(hostport); ok && d != nil {
			if md, ok := v.(*MemoryDialer); ok && md != nil {
				if d.Logger != nil {
					d.Logger.Info("http dialer switch to memory dialer", "memory_dialer_address", md.Address)
				}
				if addrport, err := netip.ParseAddrPort(addr); err == nil {
					if DailerReservedIPPrefix.Contains(addrport.Addr()) {
						// Target is a memory address, skip HTTP CONNECT
						return md.DialContext(ctx, network, hostport)
					}
				}
				dialer = md
			}
		}
	}

	conn, err := dialer.DialContext(ctx, network, hostport)
	if err != nil {
		return nil, err
	}
	closeConn := &conn
	defer func() {
		if closeConn != nil {
			(*closeConn).Close()
		}
	}()

	if d.TLS {
		if d.tlsConfig == nil {
			return nil, errors.New("httpdialer: empty tls config")
		}
		tlsConfig := d.tlsConfig
		if d.ECH {
			https, err := d.Resolver.Client.LookupHTTPS(ctx, d.Host)
			if err != nil {
				return nil, fmt.Errorf("lookup https %v error: %w", d.Host, err)
			}
			if len(https) == 0 || len(https[0].ECH) == 0 {
				return nil, fmt.Errorf("lookup https %v error: emtpy record", d.Host)
			}
			tlsConfig = tlsConfig.Clone()
			tlsConfig.MinVersion = tls.VersionTLS13
			tlsConfig.EncryptedClientHelloConfigList = https[0].ECH
		}
		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	if d.PSK != "" {
		if d.Websocket {
			return nil, fmt.Errorf("invalid psk option in websocket http diailer: %+v", d)
		}
		sha1sum := sha1.Sum(s2b(d.PSK))
		nonce := binary.LittleEndian.Uint64(sha1sum[:8])
		conn = &Chacha20NetConn{
			Conn:   conn,
			Writer: must(Chacha20NewStreamCipher([]byte(d.PSK), nonce)),
			Reader: must(Chacha20NewStreamCipher([]byte(d.PSK), nonce)),
		}
	}

	buf := AppendableBytes(make([]byte, 0, 2048))

	if !d.Websocket {
		buf = buf.Str("CONNECT ").Str(addr).Str(" HTTP/1.1\r\n")
		buf = buf.Str("Host: ").Str(addr).Str("\r\n")
	} else {
		// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-connect-tcp-05
		host, port, _ := net.SplitHostPort(addr)
		key := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%x%x\n", fastrandn(1<<32-1), fastrandn(1<<32-1)))
		buf = buf.Str("GET ").Str(HTTPWellknownBase64PathPrefix).Base64(s2b(HTTPTunnelConnectTCPPathPrefix + host + "/" + port + "/")).Str(" HTTP/1.1\r\n")
		buf = buf.Str("Host: ").Str(d.Host).Str("\r\n")
		buf = buf.Str("Connection: Upgrade\r\n")
		buf = buf.Str("Upgrade: websocket\r\n")
		buf = buf.Str("Sec-WebSocket-Version: 13\r\n")
		buf = buf.Str("Sec-WebSocket-Key: ").Str(key).Str("\r\n")
	}
	if d.Username != "" {
		buf = buf.Str("Proxy-Authorization: Basic ").Base64(s2b(d.Username + ":" + d.Password)).Str("\r\n")
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		for key, values := range header {
			for _, value := range values {
				buf = buf.Str(key).Str(": ").Str(value).Str("\r\n")
			}
		}
	}
	buf = buf.Str("User-Agent: ").Str(cmp.Or(d.UserAgent, DefaultUserAgent)).Str("\r\n")
	buf = buf.Str("\r\n")

	if _, err := conn.Write(buf); err != nil {
		return nil, errors.New("httpdialer: failed to write greeting to HTTP proxy at " + d.Host + ": " + err.Error())
	}

	// see https://github.com/golang/go/issues/5373
	buf = buf[:cap(buf)]
	for i := range buf {
		buf[i] = 0
	}

	b := buf
	total := 0

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	for {
		n, err := conn.Read(buf)
		if err != nil {
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
		return nil, fmt.Errorf("httpdialer: failed to connect %s via %s: %s", addr, d.Host, bytes.TrimRight(b, "\x00"))
	}
	for i, c := range b[n+1:] {
		if i == 3 || c < '0' || c > '9' {
			break
		}
		status = status*10 + int(c-'0')
	}
	if status != http.StatusOK && status != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("httpdialer: failed to connect %s via %s: %s", addr, d.Host, bytes.TrimRight(b, "\x00"))
	}

	closeConn = nil
	return conn, nil
}
