package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	sprig "github.com/go-task/slim-sprig/v3"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v4"
	"go4.org/netipx"
	"golang.org/x/net/publicsuffix"
)

type Functions struct {
	Logger          log.Logger
	DnsResolverPool *DnsResolverPool
	DnsResolver     *DnsResolver
	GeoResolver     *GeoResolver

	FetchUserAgent string
	FetchClient    *http.Client
	FetchCache     *lru.TTLCache[string, *FetchResponse]

	RegexpCache    *xsync.Map[string, *regexp.Regexp]
	FileLineCache  *xsync.Map[string, *FileLoader[[]string]]
	FileIPSetCache *xsync.Map[string, *FileLoader[*netipx.IPSet]]

	funcs template.FuncMap
}

func (f *Functions) FuncMap() template.FuncMap {
	return f.funcs
}

func (f *Functions) Load() error {
	f.funcs = template.FuncMap(sprig.GenericFuncMap())

	// slog helper
	f.funcs["slog"] = f.slog

	// sprig replacement
	f.funcs["get"] = f.get
	f.funcs["set"] = f.set
	f.funcs["unset"] = f.unset
	f.funcs["hasKey"] = f.hasKey
	f.funcs["tlsSNI"] = f.tlsSNI

	// sprig supplement
	f.funcs["hasPrefixes"] = f.hasPrefixes
	f.funcs["hasSuffixes"] = f.hasSuffixes
	f.funcs["regexMatch"] = f.regexMatch
	f.funcs["wildcardMatch"] = f.wildcardMatch

	// http related
	f.funcs["country"] = f.country
	f.funcs["dnsResolve"] = f.dnsResolve
	f.funcs["nslookup"] = f.nslookup
	f.funcs["domain"] = f.domain
	f.funcs["fetch"] = f.fetch
	f.funcs["geoip"] = f.geoip
	f.funcs["geosite"] = f.geosite
	f.funcs["greased"] = f.greased
	f.funcs["hasIPv6"] = f.hasIPv6
	f.funcs["host"] = f.host
	f.funcs["ipInt"] = f.ipInt
	f.funcs["ipRange"] = f.ipRange
	f.funcs["isInNet"] = f.isInNet

	// pattern matching with file
	f.funcs["inFileLine"] = f.inFileLine
	f.funcs["inFileIPSet"] = f.inFileIPSet

	// file related
	f.funcs["readFile"] = f.readfile
	f.funcs["readfile"] = f.readfile

	return nil
}

func (f *Functions) slog(msg string, args ...any) string {
	f.Logger.Info().Caller(1).KeysAndValues(args...).Msg(msg)
	return ""
}

func (f *Functions) get(dict any, key string) any {
	var value string
	switch dict := dict.(type) {
	case map[string]string:
		value = dict[key]
	case map[string]any:
		value, _ = dict[key].(string)
	}
	return value
}

func (f *Functions) set(dict any, key, value string) any {
	switch dict := dict.(type) {
	case map[string]string:
		dict[key] = value
	case map[string]any:
		dict[key] = value
	}
	return dict
}

func (f *Functions) unset(dict any, key, value string) any {
	switch dict := dict.(type) {
	case map[string]string:
		delete(dict, key)
	case map[string]any:
		delete(dict, key)
	}
	return dict
}

func (f *Functions) hasKey(dict any, key string) bool {
	var ok bool
	switch dict := dict.(type) {
	case map[string]string:
		_, ok = dict[key]
	case map[string]any:
		_, ok = dict[key]
	}
	return ok
}

func (f *Functions) host(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

func (f *Functions) geosite(domain string) string {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	return f.GeoResolver.GetGeoSiteInfo(context.Background(), domain).Site
}

func (f *Functions) geoip(ipStr string) (info GeoIPInfo) {
	if strings.IndexByte(ipStr, ':') > 0 {
		if host, _, err := net.SplitHostPort(ipStr); err == nil {
			ipStr = host
		}
	}
	if ip, err := netip.ParseAddr(ipStr); err == nil {
		info = f.GeoResolver.GetGeoIPInfo(context.Background(), ip)
	}
	return
}

func (f *Functions) country(ip string) string {
	return f.geoip(ip).Country
}

func (f *Functions) dnsResolve(host string) string {
	if s, _, err := net.SplitHostPort(host); err == nil {
		host = s
	}

	ips, _ := f.DnsResolver.LookupNetIP(context.Background(), "ip", host)
	if len(ips) != 0 {
		return ips[0].String()
	}

	return ""
}

func (f *Functions) nslookup(host string, nameservers ...string) ([]string, error) {
	var resolver *DnsResolver
	if len(nameservers) == 0 || nameservers[0] == "" {
		resolver = f.DnsResolver
	} else {
		var err error
		resolver, err = f.DnsResolverPool.Get(nameservers[0], 600*time.Second)
		if err != nil {
			return nil, err
		}
	}

	if s, _, err := net.SplitHostPort(host); err == nil {
		host = s
	}

	if addr, err := netip.ParseAddr(host); err == nil && addr.IsValid() {
		ptr, err := resolver.Client.LookupPTR(context.Background(), host)

		if err != nil {
			return nil, err
		}

		return []string{ptr}, nil
	}

	ips, err := resolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}

	return result, nil
}

func (f *Functions) domain(domain string) string {
	if s, _, err := net.SplitHostPort(domain); err == nil {
		domain = s
	}

	if _, err := netip.ParseAddr(domain); err == nil {
		return domain
	}

	s, _ := publicsuffix.EffectiveTLDPlusOne(domain)
	return s
}

func (f *Functions) greased(info *tls.ClientHelloInfo) bool {
	if info == nil || len(info.CipherSuites) == 0 {
		return false
	}
	c := info.CipherSuites[0]
	return c&0x0f0f == 0x0a0a && c&0xff == c>>8
}

type FetchResponse struct {
	Status    int
	Headers   http.Header
	Body      string
	Lines     []string
	Error     error
	CreatedAt time.Time
}

func (f *Functions) fetch(ua string, timeout, ttl int, uri string) (response FetchResponse) {
	loader := func(ctx context.Context, uri string) (*FetchResponse, time.Duration, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(ttl, 60)) * time.Second, nil
		}
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		} else {
			req.Header.Set("User-Agent", f.FetchUserAgent)
		}

		resp, err := f.FetchClient.Do(req)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(ttl, 60)) * time.Second, nil
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(ttl, 60)) * time.Second, nil
		}

		result := &FetchResponse{
			Status:    resp.StatusCode,
			Headers:   resp.Header,
			Body:      string(body),
			CreatedAt: time.Now(),
		}

		if strings.HasPrefix(result.Headers.Get("content-type"), "text/") {
			// result.Lines = strings.Split(result.Body, "\n")
			result.Lines = AppendSplitLines(make([]string, 0, strings.Count(result.Body, "\n")), result.Body)
		}

		log.Info().Str("fetch_url", uri).Int("fetch_response_status", result.Status).Any("fetch_response_headers", result.Headers).Int("fetch_response_length", len(result.Body)).Msg("fetch ok")

		return result, time.Duration(ttl), nil
	}

	resp, _, _ := f.FetchCache.GetOrLoad(context.Background(), uri, loader)
	if resp == nil {
		return
	}

	response = *resp
	return
}

func (f *Functions) ipRange(cidr string) (result IPRange) {
	result, _ = GetIPRange(strings.TrimSpace(cidr))
	return
}

func (f *Functions) ipInt(ipStr string) uint32 {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || !ip.Is4() {
		return 0
	}
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:])
}

func (f *Functions) isInNet(host, cidr string) bool {
	if s, _, err := net.SplitHostPort(host); err == nil {
		host = s
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		log.Error().Err(err).Str("host", host).Str("cidr", cidr).Msg("isInNet ParsePrefix error")
		return false
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, err := f.DnsResolver.LookupNetIP(context.Background(), "ip", host)
		if err != nil {
			log.Error().Err(err).Str("host", host).Str("cidr", cidr).Msg("isInNet LookupNetIP error")
		}
		if len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}

	return prefix.Contains(ip)
}

func (f *Functions) hasIPv6(host string) bool {
	if s, _, err := net.SplitHostPort(host); err == nil {
		host = s
	}

	ips, err := f.DnsResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.Is6() {
			return true
		}
	}

	return false
}

func (f *Functions) readfile(filename string) string {
	data, _ := os.ReadFile(filename)
	return string(data)
}

//lint:ignore U1000 Ignore unused function
func (f *Functions) contains(substr, s string) bool {
	return strings.Contains(s, substr)
}

//lint:ignore U1000 Ignore unused function
func (f *Functions) hasSuffix(suffix, s string) bool {
	return strings.HasSuffix(s, suffix)
}

//lint:ignore U1000 Ignore unused function
func (f *Functions) hasPrefix(suffix, s string) bool {
	return strings.HasPrefix(s, suffix)
}

func (f *Functions) hasSuffixes(pattern, s string) bool {
	for pattern != "" {
		var p string
		i := strings.IndexByte(pattern, '|')
		if i < 0 {
			p, pattern = pattern, ""
		} else {
			p, pattern = pattern[:i], pattern[i+1:]
		}
		if strings.HasSuffix(s, p) {
			return true
		}
	}
	return false
}

func (f *Functions) hasPrefixes(pattern, s string) bool {
	for pattern != "" {
		var p string
		i := strings.IndexByte(pattern, '|')
		if i < 0 {
			p, pattern = pattern, ""
		} else {
			p, pattern = pattern[:i], pattern[i+1:]
		}
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (f *Functions) wildcardMatch(pattern, s string) bool {
	for pattern != "" {
		var p string
		i := strings.IndexByte(pattern, '|')
		if i < 0 {
			p, pattern = pattern, ""
		} else {
			p, pattern = pattern[:i], pattern[i+1:]
		}
		if WildcardMatch(p, s) {
			return true
		}
	}
	return false
}

func (f *Functions) inFileLine(filename, line string) bool {
	filename, _ = filepath.Abs(filepath.Clean(filename))
	loader, _ := f.FileLineCache.LoadOrCompute(filename, func() (*FileLoader[[]string], bool) {
		return &FileLoader[[]string]{
			Filename: filename,
			Unmarshal: func(data []byte, v any) error {
				lines, ok := v.(*[]string)
				if !ok {
					return fmt.Errorf("*[]string required, found %T", v)
				}
				*lines = AppendSplitLines(make([]string, 0, strings.Count(b2s(data), "\n")), string(data))
				slices.Sort(*lines)
				return nil
			},
			PollDuration: 2 * time.Minute,
			Logger:       log.DefaultLogger.Slog(),
		}, false
	})
	if loader == nil {
		return false
	}

	lines := loader.Load()
	if lines == nil {
		return false
	}

	_, found := slices.BinarySearch(*lines, line)

	return found
}

func (f *Functions) inFileIPSet(filename, ipstr string) bool {
	filename, _ = filepath.Abs(filepath.Clean(filename))
	loader, _ := f.FileIPSetCache.LoadOrCompute(filename, func() (*FileLoader[*netipx.IPSet], bool) {
		return &FileLoader[*netipx.IPSet]{
			Filename: filename,
			Unmarshal: func(data []byte, v any) error {
				ipsetp, ok := v.(**netipx.IPSet)
				if !ok {
					return fmt.Errorf("**netipx.IPSet required, found %T", v)
				}
				var builder netipx.IPSetBuilder
				for line := range strings.Lines(b2s(data)) {
					line = strings.TrimSpace(line)
					switch {
					case strings.Count(line, "-") == 1:
						if iprange, err := netipx.ParseIPRange(line); err == nil {
							builder.AddRange(iprange)
						}
					case strings.Contains(line, "/"):
						if prefix, err := netip.ParsePrefix(line); err == nil {
							builder.AddPrefix(prefix)
						}
					default:
						if ip, err := netip.ParseAddr(line); err == nil {
							builder.Add(ip)
						}
					}
				}
				ipset, err := builder.IPSet()
				if err != nil {
					return err
				}
				*ipsetp = ipset
				return nil
			},
			PollDuration: 2 * time.Minute,
			Logger:       log.DefaultLogger.Slog(),
		}, false
	})
	if loader == nil {
		return false
	}

	ip, err := netip.ParseAddr(ipstr)
	if err != nil {
		return false
	}

	ipset := loader.Load()
	if ipset == nil {
		return false
	}

	return (*ipset).Contains(ip)
}

func (f *Functions) regexMatch(pattern, s string) bool {
	regex, _ := f.RegexpCache.LoadOrCompute(pattern, func() (*regexp.Regexp, bool) {
		v, _ := regexp.Compile(pattern)
		return v, false
	})
	if regex == nil {
		return false
	}
	return regex.MatchString(s)
}

type PeekingConn struct {
	net.Conn
	head []byte
}

func (c *PeekingConn) Read(b []byte) (n int, err error) {
	if len(c.head) > 0 {
		n = copy(b, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *PeekingConn) PeekTLSClientHello() (sni string, err error) {
	// 1. Read Client Hello
	head := make([]byte, 1024)
	n, err := c.Conn.Read(head)
	if err != nil {
		return "", err
	}
	c.head = head[:n]

	// 2. Parse Client Hello
	return PeekTLSClientHello(c.head)
}

func PeekTLSClientHello(data []byte) (sni string, err error) {
	// Skip record header: type(1) + version(2) + length(2)
	// Handshake header: msg_type(1) + length(3) + version(2) + random(32) + session_id_len(1)
	const RecordHeaderLen = 5
	const HandshakeHeaderLen = 4 // msg_type + length
	const MinClientHelloLen = RecordHeaderLen + HandshakeHeaderLen

	if len(data) < MinClientHelloLen {
		return "", io.ErrUnexpectedEOF
	}

	// Check for TLS Handshake (0x16) and Version (0x0301, 0x0302, 0x0303)
	if data[0] != 0x16 || data[1] < 0x03 || data[2] > 0x03 {
		return "", fmt.Errorf("not a tls handshake")
	}

	length := int(data[3])<<8 | int(data[4])
	if len(data) < RecordHeaderLen+length {
		// incomplete record, but we might have enough for sni
	}

	// Check handshake type (0x01 ClientHello)
	if data[5] != 0x01 {
		return "", fmt.Errorf("not a client hello")
	}

	// session_id_len offset: record_header(5) + handshake_header(4) + client_version(2) + random(32) = 43
	offset := 43
	if len(data) <= offset {
		return "", io.ErrUnexpectedEOF
	}

	sessionIdLen := int(data[offset])
	offset += 1 + sessionIdLen
	if len(data) <= offset+2 {
		return "", io.ErrUnexpectedEOF
	}

	// cipher_suites_len
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen
	if len(data) <= offset+1 {
		return "", io.ErrUnexpectedEOF
	}

	// compression_methods_len
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen
	if len(data) <= offset+2 {
		return "", io.ErrUnexpectedEOF
	}

	// extensions_len
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if len(data) < offset+extensionsLen {
		// we likely don't have the full extensions, but let's try to parse what we have
		extensionsLen = len(data) - offset
	}

	// Parse extensions
	end := offset + extensionsLen
	for offset+4 <= end {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if offset+extLen > end {
			break
		}

		if extType == 0x00 { // Server Name Indication
			if extLen < 2 {
				break
			}
			listLen := int(data[offset])<<8 | int(data[offset+1])
			if listLen+2 != extLen {
				break
			}
			offset += 2

			// NameType(1) + NameLen(2)
			if offset+3 > end {
				break
			}

			nameType := data[offset]
			nameLen := int(data[offset+1])<<8 | int(data[offset+2])
			offset += 3

			if nameType == 0 && offset+nameLen <= end {
				return string(data[offset : offset+nameLen]), nil
			}
		}

		offset += extLen
	}

	return "", fmt.Errorf("sni not found")
}

func (f *Functions) tlsSNI(conn net.Conn) string {
	if pc, ok := conn.(*PeekingConn); ok {
		sni, err := pc.PeekTLSClientHello()
		if err != nil {
			f.Logger.Debug().Err(err).Msg("sni peek error")
			return ""
		}
		return sni
	}
	return ""
}
