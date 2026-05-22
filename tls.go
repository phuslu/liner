package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/cpu"
)

type TLSInspectorEntry struct {
	ServerName     string
	KeyFile        string
	CertFile       string
	DisableHTTP2   bool
	DisableTLS11   bool
	PreferChacha20 bool
}

type TLSInspectorCacheKey struct {
	ServerName     string
	DisableTLS11   bool
	DisableHTTP2   bool
	HasAES         bool
	HasTLS13       bool
	HasEcsdaCipher bool
	HasChaCha20    bool
}

type TLSInspectorCacheValue struct {
	TLSConfig *tls.Config
	ExpiredAt time.Time
}

type TLSClientHelloInfo struct {
	ClientHelloInfo *tls.ClientHelloInfo
	Certificate     *tls.Certificate
	JA4             [36]byte

	Conn  net.Conn
	QConn *quic.Conn
}

func (info *TLSClientHelloInfo) NetConn() net.Conn { return info.Conn }

func (info *TLSClientHelloInfo) QuicConn() *quic.Conn { return info.QConn }

type TLSInspectorError string

func (err TLSInspectorError) Error() string { return string(err) }

const ErrTLSServerNameNotFound = TLSInspectorError("tls server name is not found")
const ErrTLSServerNameHijacked = TLSInspectorError("tls server name is hijacked")

type TLSServerNameHandle func(ctx context.Context, sni string, data []byte, conn net.Conn) error

type TLSInspector struct {
	Logger              *log.Logger
	AutoCertDir         string
	EntryMap            map[string]TLSInspectorEntry // key: TLS ServerName
	EntryWildcard       []TLSInspectorEntry
	AutoCert            *autocert.Manager
	RootCA              *RootCA
	TLSConfigCache      *xsync.Map[TLSInspectorCacheKey, TLSInspectorCacheValue]
	TLSServerNameHandle TLSServerNameHandle
}

func (m *TLSInspector) AddEntry(entry TLSInspectorEntry) error {
	if m.TLSConfigCache == nil {
		m.TLSConfigCache = xsync.NewMap[TLSInspectorCacheKey, TLSInspectorCacheValue]()
	}

	if m.AutoCert == nil {
		m.AutoCert = &autocert.Manager{
			Cache:      autocert.DirCache(cmp.Or(m.AutoCertDir, "autocert")),
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

	if addr, err := netip.ParseAddr(entry.ServerName); err == nil && addr.IsValid() {
		if entry.KeyFile == "" {
			// a pure ip server name, generate a self-sign certificate
			if err := m.RootCA.Issue(entry.ServerName); err != nil {
				return fmt.Errorf("issue ip certificate for %q: %w", entry.ServerName, err)
			}
			entry.KeyFile = filepath.Join(m.RootCA.DirName, entry.ServerName+".crt")
		}
	}

	if entry.KeyFile != "" && entry.CertFile == "" {
		entry.CertFile = entry.KeyFile
	}

	if m.EntryMap == nil {
		m.EntryMap = make(map[string]TLSInspectorEntry)
	}

	switch strings.Count(entry.ServerName, "*") {
	case 0:
		m.EntryMap[entry.ServerName] = entry
	case 1:
		m.EntryWildcard = append(m.EntryWildcard, entry)
	default:
		return errors.New("unsupported server_name: " + entry.ServerName)
	}

	return nil
}

func (m *TLSInspector) LookupEntry(serverName string) (entry TLSInspectorEntry, exists bool) {
	entry, exists = m.EntryMap[serverName]
	if exists {
		return
	}
	for _, wild := range m.EntryWildcard {
		if i := strings.IndexByte(wild.ServerName, '*'); i >= 0 {
			switch {
			case i == 0:
				exists = strings.HasSuffix(serverName, wild.ServerName[i+1:])
			case i == len(wild.ServerName)-1:
				exists = strings.HasPrefix(serverName, wild.ServerName[:i])
			default:
				exists = strings.HasSuffix(serverName, wild.ServerName[i+1:]) && strings.HasPrefix(serverName, wild.ServerName[:i])
			}
		}
		if exists {
			entry = wild
			break
		}
	}
	return
}

func (m *TLSInspector) HostPolicy(ctx context.Context, serverName string) error {
	_, ok := m.LookupEntry(serverName)
	if !ok {
		return errors.ErrUnsupported
	}
	return nil
}

func (m *TLSInspector) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	entry, ok := m.LookupEntry(hello.ServerName)
	if !ok {
		return nil, ErrTLSServerNameNotFound
	}

	if entry.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(entry.CertFile, entry.KeyFile)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}

	return m.AutoCert.GetCertificate(hello)
}

func (m *TLSInspector) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	info := HTTPClientHelloInfoFromContext(hello.Context())
	if info != nil {
		info.ClientHelloInfo = hello
		AppendJA4Fingerprint(info.JA4[:0], info.ClientHelloInfo)
	}

	entry, _ := m.LookupEntry(hello.ServerName)

	hasAES := (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) || (cpu.ARM64.HasAES && cpu.ARM64.HasPMULL)
	hasTLS13, ecsdaCipher := LookupEcdsaCiphers(hello)
	hasChaCha20 := ecsdaCipher == tls.TLS_CHACHA20_POLY1305_SHA256

	if entry.PreferChacha20 && !hasChaCha20 && hasTLS13 {
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
		ServerName:     hello.ServerName,
		DisableTLS11:   entry.DisableTLS11,
		DisableHTTP2:   entry.DisableHTTP2,
		HasAES:         hasAES,
		HasTLS13:       hasTLS13,
		HasEcsdaCipher: ecsdaCipher != 0,
		HasChaCha20:    hasChaCha20,
	}

	if v, _ := m.TLSConfigCache.Load(cacheKey); v.TLSConfig != nil && time.Now().Before(v.ExpiredAt) {
		if info != nil {
			info.Certificate = &v.TLSConfig.Certificates[0]
		}
		return v.TLSConfig, nil
	}

	cert, err := m.GetCertificate(hello)
	if err != nil {
		if err == ErrTLSServerNameNotFound && m.TLSServerNameHandle != nil {
			if mc, ok := hello.Conn.(*MirrorHeaderConn); ok {
				err := m.TLSServerNameHandle(hello.Context(), hello.ServerName, mc.Header(), mc.Conn)
				if err != nil {
					return nil, err
				}
			}
		}
		return nil, fmt.Errorf("tls inspector cannot handle server name %#v: %w", hello.ServerName, err)
	}
	if info != nil {
		info.Certificate = cert
	}

	config := &tls.Config{
		MaxVersion:               tls.VersionTLS13,
		MinVersion:               tls.VersionTLS10,
		Certificates:             []tls.Certificate{*cert},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1", "acme-tls/1"},
	}

	if entry.DisableTLS11 {
		config.MinVersion = tls.VersionTLS12
	}

	if entry.DisableHTTP2 {
		config.NextProtos = []string{"http/1.1", "acme-tls/1"}
	}

	if !hasTLS13 {
		config.MaxVersion = tls.VersionTLS12
	}

	if hasChaCha20 {
		config.PreferServerCipherSuites = false
	}

	var expiredAt time.Time
	if cert.Leaf != nil {
		expiredAt = cert.Leaf.NotAfter.Add(-6 * time.Hour)
	} else if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		expiredAt = leaf.NotAfter.Add(-6 * time.Hour)
	} else {
		expiredAt = time.Now().Add(6 * time.Hour)
	}

	m.TLSConfigCache.Store(cacheKey, TLSInspectorCacheValue{config, expiredAt})

	return config, nil
}

var HTTPClientHelloInfoContextKey any = &HTTPContextKey{"http-clienthello-info"}

func HTTPClientHelloInfoFromContext(ctx context.Context) *TLSClientHelloInfo {
	if ctx == nil {
		return nil
	}
	info, _ := ctx.Value(HTTPClientHelloInfoContextKey).(*TLSClientHelloInfo)
	return info
}

func (m *TLSInspector) HTTPConnContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, HTTPClientHelloInfoContextKey, &TLSClientHelloInfo{Conn: conn})
}

func (m *TLSInspector) HTTP3QUICConnContext(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
	return context.WithValue(ctx, HTTPClientHelloInfoContextKey, &TLSClientHelloInfo{}), nil
}

func (m *TLSInspector) HTTP3ConnContext(ctx context.Context, conn *quic.Conn) context.Context {
	if info := HTTPClientHelloInfoFromContext(ctx); info != nil {
		info.QConn = conn
	}
	return ctx
}

var _ tls.ClientSessionCache = (*TLSClientSessionCache)(nil)

type TLSClientSessionCache struct {
	lrucache *lru.LRUCache[string, *tls.ClientSessionState]
}

func (m *TLSClientSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	return m.lrucache.Get(key)
}

func (m *TLSClientSessionCache) Put(key string, state *tls.ClientSessionState) {
	m.lrucache.Set(key, state)
}
