package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phuslu/log"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/cpu"
)

type TLSVersion uint16

var (
	TLSVersion13 TLSVersion = tls.VersionTLS13
	TLSVersion12 TLSVersion = tls.VersionTLS12
	TLSVersion11 TLSVersion = tls.VersionTLS11
	TLSVersion10 TLSVersion = tls.VersionTLS10
)

func (v TLSVersion) String() string {
	switch v {
	case TLSVersion13:
		return "TLSv1.3"
	case TLSVersion12:
		return "TLSv1.2"
	case TLSVersion11:
		return "TLSv1.1"
	case TLSVersion10:
		return "TLSv1.0"
	}
	return ""
}

type TLSInspectorEntry struct {
	ServerName     string
	KeyFile        string
	CertFile       string
	DisableHTTP2   bool
	DisableTLS11   bool
	PreferChacha20 bool
	DisableOCSP    bool
}

type TLSInspectorCacheKey struct {
	ServerName     string
	DisableTLS11   bool
	DisableHTTP2   bool
	DisableOCSP    bool
	HasAES         bool
	HasTLS13       bool
	HasEcsdaCipher bool
	HasChaCha20    bool
}

type TLSInspectorCacheValue[T any] struct {
	Value     T
	CreatedAt int64
}

type TLSClientHelloInfo struct {
	*tls.ClientHelloInfo
	JA4 [36]byte
}

var ErrTLSServerNameNotFound = errors.New("tls server name is not found")

type TLSServerNameHandle func(ctx context.Context, sni string, data []byte, conn net.Conn) error

type TLSInspector struct {
	DefaultServername string

	Entries             map[string]TLSInspectorEntry // key: TLS ServerName
	AutoCert            *autocert.Manager
	RootCA              *RootCA
	TLSConfigCache      *xsync.Map[TLSInspectorCacheKey, TLSInspectorCacheValue[*tls.Config]]
	CertificateCache    *xsync.Map[TLSInspectorCacheKey, TLSInspectorCacheValue[*tls.Certificate]]
	ClientHelloMap      *xsync.Map[string, *TLSClientHelloInfo]
	TLSServerNameHandle TLSServerNameHandle
}

func (m *TLSInspector) AddCertEntry(entry TLSInspectorEntry) error {
	if m.TLSConfigCache == nil {
		m.TLSConfigCache = xsync.NewMap[TLSInspectorCacheKey, TLSInspectorCacheValue[*tls.Config]](xsync.WithSerialResize())
	}

	if m.CertificateCache == nil {
		m.CertificateCache = xsync.NewMap[TLSInspectorCacheKey, TLSInspectorCacheValue[*tls.Certificate]](xsync.WithSerialResize())
	}

	if m.AutoCert == nil {
		m.AutoCert = &autocert.Manager{
			Cache:      autocert.DirCache("certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: m.HostPolicy,
			ForceRSA:   false,
		}
	}

	if m.RootCA == nil {
		m.RootCA = &RootCA{
			DirName:    "certs",
			FileName:   "RootCA.crt",
			CommonName: "RootCA",
			Country:    "US",
			Province:   "California",
			Locality:   "Los Angeles",
			Duration:   3 * 365 * 24 * time.Hour,
			ForceRSA:   true,
		}
	}

	if net.ParseIP(entry.ServerName) != nil {
		if entry.KeyFile == "" {
			// a pure ip server name, generate a self-sign certificate
			m.RootCA.Issue(entry.ServerName)
			entry.KeyFile = filepath.Join(m.RootCA.DirName, entry.ServerName+".crt")
		}
	}

	if entry.KeyFile != "" && entry.CertFile == "" {
		entry.CertFile = entry.KeyFile
	}

	if m.Entries == nil {
		m.Entries = make(map[string]TLSInspectorEntry)
	}
	m.Entries[entry.ServerName] = entry

	return nil
}

func (m *TLSInspector) HostPolicy(ctx context.Context, host string) error {
	return nil
}

func (m *TLSInspector) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	entry, ok := m.Entries[hello.ServerName]
	if !ok {
		for key, value := range m.Entries {
			if key != "" && key[0] == '*' && strings.HasSuffix(hello.ServerName, key[1:]) {
				entry, ok = value, true
			}
		}
	}
	if !ok {
		return nil, ErrTLSServerNameNotFound
	}

	if entry.KeyFile != "" {
		cacheKey := TLSInspectorCacheKey{ServerName: entry.ServerName}
		cacheKey.HasTLS13, _ = LookupEcdsaCiphers(hello)

		if v, _ := m.CertificateCache.Load(cacheKey); v.Value != nil && time.Now().Unix()-v.CreatedAt < 24*3600 {
			return v.Value, nil
		}

		certfile, keyfile := entry.CertFile, entry.KeyFile
		if !cacheKey.HasTLS13 {
			if _, err := os.Stat(certfile + "+rsa"); err == nil {
				certfile, keyfile = certfile+"+rsa", keyfile+"+rsa"
			}
		}
		cert, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			return nil, err
		}

		m.CertificateCache.Store(cacheKey, TLSInspectorCacheValue[*tls.Certificate]{&cert, time.Now().Unix()})

		return &cert, nil
	}

	return m.AutoCert.GetCertificate(hello)
}

func (m *TLSInspector) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	m.ClientHelloMap.Store(hello.Conn.RemoteAddr().String(), &TLSClientHelloInfo{ClientHelloInfo: hello})

	if host, _, err := net.SplitHostPort(hello.ServerName); err == nil {
		hello.ServerName = host
	}

	var serverName = hello.ServerName
	if serverName == "" {
		serverName = m.DefaultServername
	}

	var preferChacha20, disableTLS11, disableHTTP2, disableOCSP bool
	if entry, ok := m.Entries[hello.ServerName]; ok {
		preferChacha20 = entry.PreferChacha20
		disableHTTP2 = entry.DisableHTTP2
		disableTLS11 = entry.DisableTLS11
		disableOCSP = entry.DisableOCSP
	}

	hasAES := (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) || (cpu.ARM64.HasAES && cpu.ARM64.HasPMULL)
	hasTLS13, ecsdaCipher := LookupEcdsaCiphers(hello)
	hasChaCha20 := ecsdaCipher == tls.TLS_CHACHA20_POLY1305_SHA256

	if preferChacha20 && !hasChaCha20 && hasTLS13 {
		i, j := -1, -1
		for index, cipher := range hello.CipherSuites {
			if !IsTLSGreaseCode(cipher) && i < 0 {
				i = index
			}
			if cipher == tls.TLS_CHACHA20_POLY1305_SHA256 {
				j = index
			}
			if 0 <= i && i < j {
				hello.CipherSuites[i], hello.CipherSuites[j] = hello.CipherSuites[j], hello.CipherSuites[i]
				hasChaCha20 = true
				break
			}
		}
	}

	cacheKey := TLSInspectorCacheKey{
		ServerName:     serverName,
		DisableTLS11:   disableTLS11,
		DisableHTTP2:   disableHTTP2,
		DisableOCSP:    disableOCSP,
		HasAES:         hasAES,
		HasTLS13:       hasTLS13,
		HasEcsdaCipher: ecsdaCipher != 0,
		HasChaCha20:    hasChaCha20,
	}

	if v, _ := m.TLSConfigCache.Load(cacheKey); v.Value != nil && time.Now().Unix()-v.CreatedAt < 24*3600 {
		return v.Value, nil
	}

	cert, err := m.GetCertificate(hello)
	if err != nil {
		if err == ErrTLSServerNameNotFound && m.TLSServerNameHandle != nil {
			if mc, ok := hello.Conn.(*MirrorHeaderConn); ok {
				err := m.TLSServerNameHandle(hello.Context(), hello.ServerName, mc.Header, mc.Conn)
				if err != nil {
					return nil, err
				}
			}
		}
		return nil, fmt.Errorf("tls inspector cannot handle server name %#v: %w", hello.ServerName, err)
	}

	cacert := cert.Leaf
	if n := len(cert.Certificate); cacert == nil && n >= 2 {
		cacert, _ = x509.ParseCertificate(cert.Certificate[n-2])
	}

	if !disableOCSP {
		ctx, cancel := context.WithTimeout(hello.Context(), 5*time.Second)
		defer cancel()
		cert.OCSPStaple, err = GetOCSPStaple(ctx, http.DefaultTransport, cacert)
		if err != nil {
			// just log error
			log.Error().Err(err).Str("server_name", serverName).Any("tls_config_cache_key", cacheKey).Msg("get ocsp response error")
		}
	}

	config := &tls.Config{
		MaxVersion:               tls.VersionTLS13,
		MinVersion:               tls.VersionTLS10,
		Certificates:             []tls.Certificate{*cert},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1", "acme-tls/1"},
	}

	if disableTLS11 {
		config.MinVersion = tls.VersionTLS12
	}

	if disableHTTP2 {
		config.NextProtos = []string{"http/1.1", "acme-tls/1"}
	}

	if !hasTLS13 {
		config.MaxVersion = tls.VersionTLS12
	}

	if hasChaCha20 {
		config.PreferServerCipherSuites = false
	}

	m.TLSConfigCache.Store(cacheKey, TLSInspectorCacheValue[*tls.Config]{config, time.Now().Unix()})

	return config, nil
}

var HTTP3ClientHelloInfoContextKey = struct{}{}

func (m *TLSInspector) HTTP3ConnContext(ctx context.Context, conn *quic.Conn) context.Context {
	addr := conn.RemoteAddr().String()
	if info, ok := m.ClientHelloMap.Load(addr); ok {
		AppendJA4Fingerprint(info.JA4[:0], TLSVersion(conn.ConnectionState().TLS.Version), info.ClientHelloInfo, true)
		ctx = context.WithValue(ctx, HTTP3ClientHelloInfoContextKey, info)
		m.ClientHelloMap.Delete(addr)
	}

	return ctx
}

func (m *TLSInspector) HTTPConnState(c net.Conn, cs http.ConnState) {
	switch cs {
	case http.StateActive:
		if info, ok := m.ClientHelloMap.Load(c.RemoteAddr().String()); ok {
			if tc, ok := c.(interface {
				ConnectionState() tls.ConnectionState
			}); ok {
				cs := tc.ConnectionState()
				AppendJA4Fingerprint(info.JA4[:0], TLSVersion(cs.Version), info.ClientHelloInfo, false)
			}
		}
	case http.StateHijacked, http.StateClosed:
		m.ClientHelloMap.Delete(c.RemoteAddr().String())
	}
}
