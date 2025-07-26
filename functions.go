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
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/go-task/slim-sprig/v3"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v4"
	"go4.org/netipx"
	"golang.org/x/net/publicsuffix"
)

type Functions struct {
	GeoResolver *GeoResolver

	FetchUserAgent string
	FetchClient    *http.Client
	FetchCache     *lru.TTLCache[string, *FetchResponse]

	RegexpCache    *xsync.Map[string, *regexp.Regexp]
	FileLineCache  *xsync.Map[string, *FileLoader[[]string]]
	FileIPSetCache *xsync.Map[string, *FileLoader[*netipx.IPSet]]

	FuncMap template.FuncMap
}

func (f *Functions) Load() error {
	f.FuncMap = template.FuncMap(sprig.GenericFuncMap())

	// sprig supplement
	f.FuncMap["hasPrefixes"] = f.hasPrefixes
	f.FuncMap["hasSuffixes"] = f.hasSuffixes
	f.FuncMap["regexMatch"] = f.regexMatch
	f.FuncMap["wildcardMatch"] = f.wildcardMatch

	// http related
	f.FuncMap["country"] = f.country
	f.FuncMap["dnsResolve"] = f.dnsResolve
	f.FuncMap["domain"] = f.domain
	f.FuncMap["fetch"] = f.fetch
	f.FuncMap["geoip"] = f.geoip
	f.FuncMap["geosite"] = f.geosite
	f.FuncMap["greased"] = f.greased
	f.FuncMap["hasIPv6"] = f.hasIPv6
	f.FuncMap["host"] = f.host
	f.FuncMap["ipInt"] = f.ipInt
	f.FuncMap["ipRange"] = f.ipRange
	f.FuncMap["isInNet"] = f.isInNet

	// pattern matching with file
	f.FuncMap["inFileLine"] = f.inFileLine
	f.FuncMap["inFileIPSet"] = f.inFileIPSet

	// file related
	f.FuncMap["readFile"] = f.readfile
	f.FuncMap["readfile"] = f.readfile

	return nil
}

func (f *Functions) host(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

func (f *Functions) geosite(domain string) string {
	return f.GeoResolver.GetGeoSiteInfo(context.Background(), domain).Site
}

func (f *Functions) geoip(ipStr string) (info GeoIPInfo) {
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

	ips, _ := f.GeoResolver.Resolver.LookupNetIP(context.Background(), "ip", host)
	if len(ips) != 0 {
		return ips[0].String()
	}

	return ""
}

func (f *Functions) domain(domain string) string {
	if s, _, err := net.SplitHostPort(domain); err == nil {
		domain = s
	}

	if net.ParseIP(domain) != nil {
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
		ips, err := f.GeoResolver.Resolver.LookupNetIP(context.Background(), "ip", host)
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

	ips, err := f.GeoResolver.Resolver.LookupNetIP(context.Background(), "ip", host)
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

func (f *Functions) contains(substr, s string) bool {
	return strings.Contains(s, substr)
}

func (f *Functions) hasSuffix(suffix, s string) bool {
	return strings.HasSuffix(s, suffix)
}

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
