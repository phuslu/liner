package main

import (
	"cmp"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mileusna/useragent"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/phuslu/geosite"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/robfig/cron/v3"
	"go4.org/netipx"
	"golang.org/x/net/http2"
)

var (
	version = "1984"
	timeNow = time.Now

	DefaultUserAgent = "Liner/" + version
	ChromeUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)

func main() {
	filename := "-"
	for _, arg := range slices.Backward(os.Args) {
		switch {
		case arg == "-version" || arg == "--version":
			println(version)
			return
		case strings.HasSuffix(arg, ".yaml") || strings.HasSuffix(arg, ".json"):
			filename = arg
		}
	}
	if runtime.GOOS == "windows" && len(os.Args) == 1 {
		if exe, err := os.Executable(); err == nil {
			name := exe[:len(exe)-len(filepath.Ext(exe))] + ".yaml"
			if _, err := os.Stat(name); err == nil {
				filename = name
			}
		}
	}
	if s := os.Getenv("LINERCONFIG"); s != "" {
		filename = s
	}

	config, err := NewConfig(filename)
	if err != nil {
		log.Fatal().Err(err).Str("filename", filename).Msg("NewConfig() error")
		os.Exit(1)
	}

	if g, p, m := runtime.Version(), os.Getenv("GOMAXPROCS"), GetMaxProcsFromCgroupV2(); g < "go1.25" && p == "" && m > 0 {
		runtime.GOMAXPROCS(m)
	}

	RegisterMimeTypes()

	// main and data logger
	var dataLogger log.Logger
	if config.Global.LogLevel == "discard" {
		log.DefaultLogger = log.Logger{
			Level:  log.ParseLevel("error"),
			Writer: log.IOWriter{io.Discard},
		}
		dataLogger = log.DefaultLogger
	} else if log.IsTerminal(os.Stderr.Fd()) {
		log.DefaultLogger = log.Logger{
			Level:      log.ParseLevel(cmp.Or(config.Global.LogLevel, "info")),
			Caller:     1,
			TimeFormat: "15:04:05",
			Writer: &log.ConsoleWriter{
				ColorOutput:    true,
				EndWithMessage: true,
			},
		}
		dataLogger = log.DefaultLogger
	} else {
		logDir := cmp.Or(config.Global.LogDir, filepath.Dir(must(os.Executable())))
		logName := filename[:len(filename)-len(filepath.Ext(filename))]
		// main logger
		log.DefaultLogger = log.Logger{
			Level:  log.ParseLevel(cmp.Or(config.Global.LogLevel, "info")),
			Caller: 1,
			Writer: &log.FileWriter{
				Filename:     filepath.Join(logDir, logName+".log"),
				MaxBackups:   1,
				MaxSize:      cmp.Or(config.Global.LogMaxsize, 10*1024*1024),
				LocalTime:    config.Global.LogLocaltime,
				EnsureFolder: true,
			},
		}
		// data logger
		dataLogger = log.Logger{
			Writer: &log.AsyncWriter{
				ChannelSize: cmp.Or(config.Global.LogChannelSize, 8192),
				Writer: &log.FileWriter{
					Filename:     filepath.Join(logDir, "data."+logName+".log"),
					MaxBackups:   cmp.Or(config.Global.LogBackups, 2),
					MaxSize:      cmp.Or(config.Global.LogMaxsize, 20*1024*1024),
					LocalTime:    config.Global.LogLocaltime,
					EnsureFolder: true,
				},
			},
		}
		// stderr redirection
		RedirectOutputToFile(filepath.Join(logDir, logName+".error.log"))
	}

	slog.SetDefault(log.DefaultLogger.Slog())

	// global resolver with geo support
	if config.Global.DnsServer == "" {
		if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			if m := regexp.MustCompile(`(^|\n)\s*nameserver\s+(\S+)`).FindAllStringSubmatch(string(data), -1); len(m) != 0 {
				config.Global.DnsServer = cmp.Or(m[0][2], "https://8.8.8.8/dns-query")
			}
		}
	}
	resolver := &GeoResolver{
		Resolver:          must(GetResolver(config.Global.DnsServer, cmp.Or(config.Global.DnsCacheSize, DefaultDNSCacheSize))),
		Logger:            &log.DefaultLogger,
		EnableCJKCityName: true,
	}
	if names, err := filepath.Glob(filepath.Join(config.Global.GeoipDir, "*.mmdb")); err == nil {
		newerdb := func(r1, r2 *maxminddb.Reader) *maxminddb.Reader {
			if r1 == nil || r1.Metadata.BuildEpoch < r2.Metadata.BuildEpoch {
				return r2
			}
			return r1
		}
		for _, name := range names {
			reader, err := maxminddb.Open(name)
			if err != nil {
				log.Fatal().Err(err).Str("geoip_database_name", name).Msg("load geoip database error")
			}
			switch reader.Metadata.DatabaseType {
			case "GeoIP2-City":
				resolver.CityReader = newerdb(resolver.CityReader, reader)
			case "GeoIP2-ISP":
				resolver.ISPReader = newerdb(resolver.ISPReader, reader)
			case "GeoIP2-Domain":
				resolver.DomainReader = newerdb(resolver.DomainReader, reader)
			case "GeoIP2-Connection-Type":
				resolver.ConnectionTypeReader = newerdb(resolver.ConnectionTypeReader, reader)
			case "GeoIP2-ASN":
				break
			case "GeoLite2-City":
				resolver.CityReader = newerdb(resolver.CityReader, reader)
			case "GeoLite2-ISP":
				resolver.ISPReader = newerdb(resolver.ISPReader, reader)
			case "GeoLite2-Domain":
				resolver.DomainReader = newerdb(resolver.DomainReader, reader)
			case "GeoLite2-Connection-Type":
				resolver.ConnectionTypeReader = newerdb(resolver.ConnectionTypeReader, reader)
			case "GeoLite2-ASN":
				break
			}
			log.Info().Str("geoip_database_name", name).Str("geoip_database_type", reader.Metadata.DatabaseType).Time("geoip_database_date", time.Unix(int64(reader.Metadata.BuildEpoch), 0)).Msg("load geoip database ok")
		}
	}
	if cmp.Or(resolver.CityReader, resolver.ISPReader, resolver.DomainReader, resolver.ConnectionTypeReader) != nil {
		resolver.GeoIPCache = lru.NewTTLCache[netip.Addr, GeoIPInfo](cmp.Or(config.Global.GeoipCacheSize, 8192))
	}

	// global dialer
	dialer := &LocalDialer{
		Logger:          slog.Default(),
		Resolver:        resolver.Resolver,
		Concurrency:     2,
		PerferIPv6:      false,
		ForbidLocalAddr: config.Global.ForbidLocalAddr,
		ReadBuffSize:    config.Global.DialReadBuffer,
		WriteBuffSize:   config.Global.DialWriteBuffer,
		DialTimeout:     time.Duration(cmp.Or(config.Global.DialTimeout, 15)) * time.Second,
		TCPKeepAlive:    30 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: config.Global.TlsInsecure,
			ClientSessionCache: tls.NewLRUClientSessionCache(2048),
		},
	}

	// dialer builder
	dialerof := func(u *url.URL, underlay Dialer) Dialer {
		switch u.Scheme {
		case "local":
			return &LocalDialer{
				Resolver:        resolver.Resolver,
				Interface:       u.Host,
				PerferIPv6:      u.Query().Get("prefer_ipv6") == "true",
				Concurrency:     2,
				ForbidLocalAddr: config.Global.ForbidLocalAddr,
				DialTimeout:     time.Duration(cmp.Or(first(strconv.Atoi(u.Query().Get("dial_timeout"))), config.Global.DialTimeout, 15)) * time.Second,
				TCPKeepAlive:    30 * time.Second,
				TLSConfig: &tls.Config{
					InsecureSkipVerify: u.Query().Get("insecure") == "true",
					ClientSessionCache: tls.NewLRUClientSessionCache(2048),
				},
			}
		case "http", "https", "ws", "wss":
			return &HTTPDialer{
				Username:   u.User.Username(),
				Password:   first(u.User.Password()),
				Host:       u.Hostname(),
				Port:       cmp.Or(u.Port(), map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443"}[u.Scheme]),
				TLS:        u.Scheme == "https" || u.Scheme == "wss",
				PSK:        u.Query().Get("psk"),
				Websocket:  u.Scheme == "ws" || u.Scheme == "wss",
				UserAgent:  cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent),
				Insecure:   u.Query().Get("insecure") == "true",
				ECH:        u.Query().Get("ech") == "true",
				CACert:     u.Query().Get("cacert"),
				ClientKey:  u.Query().Get("key"),
				ClientCert: u.Query().Get("cert"),
				Logger:     slog.Default(),
				Resolve:    map[string]string{u.Host: u.Query().Get("resolve")},
				Dialer:     underlay,
				Resolver:   resolver.Resolver,
			}
		case "http2":
			return &HTTP2Dialer{
				Username:   u.User.Username(),
				Password:   first(u.User.Password()),
				Host:       u.Hostname(),
				Port:       u.Port(),
				UserAgent:  cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent),
				Insecure:   u.Query().Get("insecure") == "true",
				CACert:     u.Query().Get("cacert"),
				ClientKey:  u.Query().Get("key"),
				ClientCert: u.Query().Get("cert"),
				MaxClients: cmp.Or(first(strconv.Atoi(u.Query().Get("max_clients"))), 8),
				Logger:     slog.Default(),
				Dialer:     underlay,
			}
		case "http3", "http3+wss":
			return &HTTP3Dialer{
				Username:  u.User.Username(),
				Password:  first(u.User.Password()),
				Host:      u.Hostname(),
				Port:      u.Port(),
				UserAgent: cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent),
				Insecure:  u.Query().Get("insecure") == "true",
				Resolve:   u.Query().Get("resolve"),
				Websocket: strings.HasSuffix(u.Scheme, "+wss"),
				Logger:    slog.Default(),
			}
		case "socks4", "socks4a", "socks", "socks5", "socks5h":
			return &SocksDialer{
				Username: u.User.Username(),
				Password: first(u.User.Password()),
				Host:     u.Hostname(),
				Port:     u.Port(),
				PSK:      u.Query().Get("psk"),
				Socks4:   u.Scheme == "socks4" || u.Scheme == "socks4a",
				Socks4A:  u.Scheme == "socks4a",
				Socks5:   u.Scheme == "socks" || u.Scheme == "socks5" || u.Scheme == "socks5h",
				Socks5H:  u.Scheme == "socks5h",
				Logger:   slog.Default(),
				Resolver: resolver.Resolver,
				Dialer:   underlay,
			}
		case "ssh", "ssh2":
			return &SSHDialer{
				Username:              u.User.Username(),
				Password:              first(u.User.Password()),
				PrivateKey:            string(first(os.ReadFile(u.Query().Get("key")))),
				Host:                  u.Hostname(),
				Port:                  cmp.Or(u.Port(), "22"),
				StrictHostKeyChecking: cmp.Or(u.Query().Get("StrictHostKeyChecking") == "yes", u.Query().Get("strict_host_key_checking") == "yes"),
				UserKnownHostsFile:    cmp.Or(u.Query().Get("UserKnownHostsFile"), u.Query().Get("user_known_hosts_file")),
				MaxClients:            cmp.Or(first(strconv.Atoi(u.Query().Get("max_clients"))), 1),
				Timeout:               time.Duration(cmp.Or(first(strconv.Atoi(u.Query().Get("timeout"))), 10)) * time.Second,
				IdleTimeout:           time.Duration(cmp.Or(first(strconv.Atoi(u.Query().Get("idle_timeout"))), 600)) * time.Second,
				TcpReadBuffer:         cmp.Or(first(strconv.Atoi(u.Query().Get("tcp_read_buffer"))), 128*1024),
				TcpWriteBuffer:        cmp.Or(first(strconv.Atoi(u.Query().Get("tcp_write_buffer"))), 128*1024),
				Logger:                slog.Default(),
				Dialer:                underlay,
			}
		default:
			log.Fatal().Str("dialer_scheme", u.Scheme).Msgf("unsupported dialer=%+v", u)
		}
		return nil
	}

	dialers := make(map[string]Dialer)
	for name, s := range config.Dialer {
		var d Dialer = dialer
		for line := range strings.Lines(s) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			u, err := url.Parse(line)
			if err != nil {
				log.Fatal().Err(err).Str("dialer_url", s).Msg("parse dailer url failed")
			}
			d = dialerof(u, d)
		}
		dialers[name] = d
	}

	// see http.DefaultTransport
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		// DialTLSContext:        dialer.DialTLSContext,
		TLSClientConfig:       dialer.TLSConfig,
		MaxIdleConns:          cmp.Or(config.Global.MaxIdleConns, 100),
		IdleConnTimeout:       time.Duration(cmp.Or(config.Global.IdleConnTimeout, 90)) * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		DisableCompression:    false,
	}

	// set geosite to geo resolver
	if !config.Global.GeositeDisabled {
		resolver.GeoSiteCache = lru.NewTTLCache[string, GeoSiteInfo](cmp.Or(config.Global.GeositeCacheSize, 8192))
		resolver.GeoSiteDLC = &geosite.DomainListCommunity{Transport: transport}
		resolver.GeoSiteDLC.Load(context.Background(), geosite.InlineTarball)
		go func() {
			for range time.Tick(time.Hour) {
				if err := resolver.GeoSiteDLC.Load(context.Background(), geosite.OnlineTarball); err != nil {
					log.Error().Err(err).Str("geosite_online_tarball", geosite.OnlineTarball).Msg("geosite load error")
				}
			}
		}()
	}

	// useragent caching map
	useragentMap := NewCachingMap(
		func(key string) (useragent.UserAgent, error) {
			return useragent.Parse(key), nil
		},
		4096,
		5*time.Minute,
	)

	// template functions
	functions := &Functions{
		GeoResolver:    resolver,
		FetchUserAgent: ChromeUserAgent,
		FetchClient:    &http.Client{Transport: transport},
		FetchCache:     lru.NewTTLCache[string, *FetchResponse](1024),
		RegexpCache:    xsync.NewMap[string, *regexp.Regexp](xsync.WithSerialResize()),
		FileLineCache:  xsync.NewMap[string, *FileLoader[[]string]](xsync.WithSerialResize()),
		FileIPSetCache: xsync.NewMap[string, *FileLoader[*netipx.IPSet]](xsync.WithSerialResize()),
	}
	if err := functions.Load(); err != nil {
		log.Fatal().Err(err).Msgf("%T.Load() fatal", functions)
	}
	log.Info().Msgf("%T.Load() ok", functions)

	lc := ListenConfig{
		FastOpen:    false,
		ReusePort:   true,
		DeferAccept: true,
	}

	memoryListeners := new(sync.Map)
	for _, sshConfig := range config.Ssh {
		for _, listen := range sshConfig.Listen {
			memoryListeners.Store(listen, nil)
		}
	}
	for _, httpConfig := range config.Http {
		for _, listen := range httpConfig.Listen {
			memoryListeners.Store(listen, nil)
		}
	}

	memoryDialers := new(sync.Map)

	servers := make([]*http.Server, 0)

	// tls inspector
	tlsConfigurator := &TLSInspector{
		Logger:         &log.DefaultLogger,
		AutoCertDir:    config.Global.AutocertDir,
		ClientHelloMap: xsync.NewMap[PlainAddr, *TLSClientHelloInfo](xsync.WithSerialResize()),
	}

	// sni proxy
	if config.Sni.Enabled {
		handler := &SniHandler{
			Config:      config.Sni,
			GeoResolver: resolver,
			LocalDialer: dialer,
			Dialers:     dialers,
			Functions:   functions.FuncMap(),
		}
		err = handler.Load()
		if err != nil {
			log.Fatal().Err(err).Msgf("%T.Load() return error: %+v", handler, err)
		}
		log.Info().Msgf("%T.Load() ok", handler)

		tlsConfigurator.TLSServerNameHandle = handler.ServeConn
	}

	// listen and serve https
	h2handlers := map[string]*struct {
		Names map[string]HTTPHandler
		Affix []struct {
			Prefix  string
			Suffix  string
			Handler HTTPHandler
		}
	}{}
	for _, server := range config.Https {
		handler := &HTTPServerHandler{
			ForwardHandler: &HTTPForwardHandler{
				Config:         server,
				DataLogger:     dataLogger,
				MemoryDialers:  memoryDialers,
				LocalDialer:    dialer,
				LocalTransport: transport,
				Dialers:        dialers,
				DialerURLs:     config.Dialer,
				GeoResolver:    resolver,
				Functions:      functions.FuncMap(),
			},
			TunnelHandler: &HTTPTunnelHandler{
				Config:        server,
				MemoryDialers: memoryDialers,
			},
			WebHandler: &HTTPWebHandler{
				Config:    server,
				Transport: transport,
				Functions: functions.FuncMap(),
			},
			Hostnames: filter(server.ServerName, func(s string) bool {
				return !strings.Contains(s, "*")
			}),
			HostnameAffix: filtermap(server.ServerName, func(s string) ([2]string, bool) {
				switch strings.Count(s, "*") {
				case 0:
					return [2]string{"", ""}, false
				case 1:
					i := strings.Index(s, "*")
					return [2]string{s[:i], s[i+1:]}, true
				default:
					panic("unsupported server_name: " + s)
				}
			}),
			ClientHelloMap: tlsConfigurator.ClientHelloMap,
			UserAgentMap:   useragentMap,
			GeoResolver:    resolver,
			Config:         server,
		}

		for _, h := range []HTTPHandler{
			handler.ForwardHandler,
			handler.TunnelHandler,
			handler.WebHandler,
			handler,
		} {
			err = h.Load()
			if err != nil {
				log.Fatal().Err(err).Strs("server_name", server.ServerName).Msgf("%T.Load() return error: %+v", h, err)
			}
			log.Info().Strs("server_name", server.ServerName).Msgf("%T.Load() ok", h)
		}

		// add support for ip tls certificate
		if len(server.ServerName) > 0 && net.ParseIP(server.ServerName[0]) != nil {
			server.ServerName = append(server.ServerName, "")
		}

		for _, listen := range server.Listen {
			for _, name := range server.ServerName {
				config, _ := server.ServerConfig[name]
				if config.Keyfile == "" {
					config.Keyfile, config.Certfile = server.Keyfile, server.Certfile
				}
				if config.Certfile == "" {
					config.Certfile = config.Keyfile
				}
				tlsConfigurator.AddTLSInspectorEntry(TLSInspectorEntry{
					ServerName:     name,
					KeyFile:        config.Keyfile,
					CertFile:       config.Certfile,
					DisableHTTP2:   config.DisableHttp2,
					DisableTLS11:   config.DisableTls11,
					PreferChacha20: config.PreferChacha20,
					DisableOCSP:    config.DisableOcsp,
				})
				if _, ok := h2handlers[listen]; !ok {
					h2handlers[listen] = &struct {
						Names map[string]HTTPHandler
						Affix []struct {
							Prefix  string
							Suffix  string
							Handler HTTPHandler
						}
					}{
						Names: make(map[string]HTTPHandler),
					}
				}
				switch strings.Count(name, "*") {
				case 0:
					h2handlers[listen].Names[name] = handler
				case 1:
					i := strings.IndexByte(name, '*')
					h2handlers[listen].Affix = append(h2handlers[listen].Affix, struct {
						Prefix  string
						Suffix  string
						Handler HTTPHandler
					}{
						Prefix:  name[:i],
						Suffix:  name[i+1:],
						Handler: handler,
					})
				default:
					panic("unsupported wildcard servername: " + name)
				}
			}
		}
	}

	for addr, handlers := range h2handlers {
		addr, handlers := addr, handlers

		var ln net.Listener

		if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
			log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
		}

		log.Info().Str("version", version).NetAddr("address", ln.Addr()).Msg("liner listen and serve https")

		server := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if s, _, err := net.SplitHostPort(r.TLS.ServerName); err == nil {
					r.TLS.ServerName = s
				}
				servername := r.TLS.ServerName
				h, matched := handlers.Names[servername]
				if !matched {
					for _, affix := range handlers.Affix {
						switch {
						case affix.Prefix == "":
							matched = strings.HasSuffix(servername, affix.Suffix)
						case affix.Suffix == "":
							matched = strings.HasPrefix(servername, affix.Prefix)
						default:
							matched = strings.HasPrefix(servername, affix.Prefix) && strings.HasSuffix(servername, affix.Suffix)
						}
						if matched {
							h = affix.Handler
							break
						}
					}
				}
				if !matched {
					http.NotFound(w, r)
					return
				}
				h.ServeHTTP(w, r)
			}),
			TLSConfig: &tls.Config{
				GetConfigForClient: tlsConfigurator.GetConfigForClient,
			},
			ConnState: tlsConfigurator.HTTPConnState,
			ErrorLog:  log.DefaultLogger.Std("", 0),
		}

		http2.ConfigureServer(server, &http2.Server{
			MaxConcurrentStreams:         100,
			MaxUploadBufferPerStream:     1024 * 1024,
			MaxUploadBufferPerConnection: 100 * 1024 * 1024, // 100 MB, https: //github.com/golang/go/issues/54330#issuecomment-1213576274
			MaxReadFrameSize:             1024 * 1024,       // 1MB read frame, https://github.com/golang/go/issues/47840
		})

		go server.Serve(TCPListener{
			TCPListener:     ln.(*net.TCPListener),
			KeepAlivePeriod: 3 * time.Minute,
			ReadBufferSize:  config.Global.TcpReadBuffer,
			WriteBufferSize: config.Global.TcpWriteBuffer,
			MirrorHeader:    true,
			TLSConfig:       server.TLSConfig,
		})

		servers = append(servers, server)

		// start http3 server
		if !config.Global.DisableHttp3 {
			go (&http3.Server{
				Addr:      addr,
				Handler:   server.Handler,
				TLSConfig: server.TLSConfig,
				QUICConfig: &quic.Config{
					Allow0RTT:                  true,
					DisablePathMTUDiscovery:    false,
					EnableDatagrams:            true,
					MaxIncomingStreams:         100,
					MaxStreamReceiveWindow:     12 * 1024 * 1024,
					MaxConnectionReceiveWindow: 200 * 1024 * 1024,
				},
				ConnContext: tlsConfigurator.HTTP3ConnContext,
				Logger:      log.DefaultLogger.Slog().With("logger", "http3_server"),
			}).ListenAndServe()
		}
	}

	// listen and serve http
	h1handlers := map[string]struct {
		HTTPHandler HTTPHandler
		PSK         []byte
	}{}
	for _, httpConfig := range config.Http {
		httpConfig.ServerName = append(httpConfig.ServerName, "", "localhost", "127.0.0.1")
		if name, err := os.Hostname(); err == nil {
			httpConfig.ServerName = append(httpConfig.ServerName, name)
		}
		if ip, err := GetPreferedLocalIP("1.1.1.1"); err == nil {
			httpConfig.ServerName = append(httpConfig.ServerName, ip.String())
		}
		handler := &HTTPServerHandler{
			ForwardHandler: &HTTPForwardHandler{
				Config:         httpConfig,
				DataLogger:     dataLogger,
				MemoryDialers:  memoryDialers,
				LocalDialer:    dialer,
				LocalTransport: transport,
				Dialers:        dialers,
				DialerURLs:     config.Dialer,
				GeoResolver:    resolver,
				Functions:      functions.FuncMap(),
			},
			TunnelHandler: &HTTPTunnelHandler{
				Config:        httpConfig,
				MemoryDialers: memoryDialers,
			},
			WebHandler: &HTTPWebHandler{
				Config:    httpConfig,
				Transport: transport,
				Functions: functions.FuncMap(),
			},
			Hostnames: filter(httpConfig.ServerName, func(s string) bool {
				return !strings.Contains(s, "*")
			}),
			HostnameAffix: filtermap(httpConfig.ServerName, func(s string) ([2]string, bool) {
				switch strings.Count(s, "*") {
				case 0:
					return [2]string{"", ""}, false
				case 1:
					i := strings.Index(s, "*")
					return [2]string{s[:i], s[i+1:]}, true
				default:
					panic("unsupported server_name: " + s)
				}
			}),
			ClientHelloMap: tlsConfigurator.ClientHelloMap,
			UserAgentMap:   useragentMap,
			GeoResolver:    resolver,
			Config:         httpConfig,
		}

		for _, h := range []HTTPHandler{
			handler.ForwardHandler,
			handler.TunnelHandler,
			handler.WebHandler,
			handler,
		} {
			err = h.Load()
			if err != nil {
				log.Fatal().Err(err).Strs("server_name", httpConfig.ServerName).Msgf("%T.Load() return error: %+v", h, err)
			}
			log.Info().Strs("server_name", httpConfig.ServerName).Msgf("%T.Load() ok", h)
		}

		for _, listen := range httpConfig.Listen {
			h1handlers[listen] = struct {
				HTTPHandler HTTPHandler
				PSK         []byte
			}{
				HTTPHandler: handler,
				PSK:         []byte(httpConfig.PSK),
			}
		}
	}

	for addr, handler := range h1handlers {
		addr, handler := addr, handler

		server := &http.Server{
			Handler:   handler.HTTPHandler,
			ErrorLog:  log.DefaultLogger.Std("", 0),
			ConnState: tlsConfigurator.HTTPConnState,
		}

		var ln net.Listener

		if _, ok := memoryListeners.Load(addr); ok && DailerReservedIPPrefix.Contains(netip.MustParseAddrPort(addr).Addr()) {
			log.Info().Str("version", version).Str("address", addr).Msg("liner listen and serve in memory")
			mln := &MemoryListener{}
			memoryListeners.Store(addr, mln)
			ln = mln
		} else {
			if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
			}
			log.Info().Str("version", version).NetAddr("address", ln.Addr()).Msg("liner listen and serve http")
			ln = TCPListener{
				TCPListener:     ln.(*net.TCPListener),
				KeepAlivePeriod: 3 * time.Minute,
				ReadBufferSize:  config.Global.TcpReadBuffer,
				WriteBufferSize: config.Global.TcpWriteBuffer,
				MirrorHeader:    false,
				PSK:             handler.PSK,
			}
		}

		go server.Serve(ln)

		servers = append(servers, server)
	}

	// socks handler
	for _, socksConfig := range config.Socks {
		for _, addr := range socksConfig.Listen {
			var ln net.Listener

			if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
			}

			log.Info().Str("version", version).NetAddr("address", ln.Addr()).Msg("liner listen and serve socks")

			h := &SocksHandler{
				Config:      socksConfig,
				DataLogger:  dataLogger,
				GeoResolver: resolver,
				LocalDialer: dialer,
				Dialers:     dialers,
				Functions:   functions.FuncMap(),
			}

			if err = h.Load(); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("socks handler load error")
			}

			go func(ln net.Listener, psk string, h *SocksHandler) {
				for {
					conn, err := ln.Accept()
					if err != nil {
						log.Error().Err(err).Str("version", version).NetAddr("address", ln.Addr()).Msg("liner accept socks connection error")
						time.Sleep(10 * time.Millisecond)
						continue
					}
					if psk != "" {
						sha1sum := sha1.Sum(s2b(psk))
						nonce := binary.LittleEndian.Uint64(sha1sum[:8])
						conn = &Chacha20NetConn{
							Conn:   conn,
							Writer: must(Chacha20NewStreamCipher([]byte(psk), nonce)),
							Reader: must(Chacha20NewStreamCipher([]byte(psk), nonce)),
						}
					}
					go h.ServeConn(context.Background(), conn)
				}
			}(ln, socksConfig.PSK, h)
		}
	}

	// stream handler
	for _, streamConfig := range config.Stream {
		for _, addr := range streamConfig.Listen {
			var ln net.Listener

			if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
			}

			log.Info().Str("version", version).NetAddr("address", ln.Addr()).Msg("liner listen and forward port")

			h := &StreamHandler{
				Config:      streamConfig,
				DataLogger:  dataLogger,
				GeoResolver: resolver,
				LocalDialer: dialer,
				Dialers:     dialers,
			}

			if err = h.Load(); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("stream handler load error")
			}

			go func(ln net.Listener, h *StreamHandler) {
				for {
					conn, err := ln.Accept()
					if err != nil {
						log.Error().Err(err).Str("version", version).NetAddr("address", ln.Addr()).Msg("liner accept stream connection error")
						time.Sleep(10 * time.Millisecond)
						continue
					}
					go h.ServeConn(conn)
				}
			}(ln, h)
		}
	}

	// ssh handler
	for _, ssh := range config.Ssh {
		for _, addr := range ssh.Listen {
			h := &SshHandler{
				Config:    ssh,
				Functions: functions.FuncMap(),
				Logger:    log.DefaultLogger,
			}

			var ln net.Listener

			if _, ok := memoryListeners.Load(addr); ok && DailerReservedIPPrefix.Contains(netip.MustParseAddrPort(addr).Addr()) {
				log.Info().Str("version", version).Str("address", addr).Msg("liner listen and serve ssh in memory")
				mln := &MemoryListener{}
				memoryListeners.Store(addr, mln)
				ln = mln
			} else {
				if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
					log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
				}
				log.Info().Str("version", version).NetAddr("address", ln.Addr()).Msg("liner listen and serve ssh")
			}

			if err = h.Load(); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("ssh handler load error")
			}

			go h.Serve(context.Background(), ln)
		}
	}

	// tunnel handler
	for _, tunnel := range config.Tunnel {
		h := &TunnelHandler{
			Config:          tunnel,
			MemoryListeners: memoryListeners,
			Resolver:        resolver.Resolver,
			LocalDialer:     dialer,
			Dialers:         config.Dialer,
		}
		if tunnel.Resolver != "" {
			h.Resolver = must(GetResolver(tunnel.Resolver, 0))
		}

		go h.Serve(context.Background())
	}

	// dns handler
	for _, dns := range config.Dns {
		for _, addr := range dns.Listen {
			if !strings.Contains(addr, "://") {
				addr = "udp://" + addr
			}
			u, err := url.Parse(addr)
			if err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("dns handler parse addr error")
			}

			h := &DnsHandler{
				Config:     dns,
				Functions:  functions.FuncMap(),
				DataLogger: dataLogger,
			}
			if err = h.Load(); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("dns handler load error")
			}

			switch u.Scheme {
			case "udp":
				pc, err := lc.ListenPacket(context.Background(), "udp", u.Host)
				if err != nil {
					log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
				}
				log.Info().Str("version", version).NetAddr("address", pc.LocalAddr()).Msg("liner listen and serve dns port")
				go h.Serve(context.Background(), pc.(*net.UDPConn))
			case "tcp":
				ln, err := lc.Listen(context.Background(), "tcp", u.Host)
				if err != nil {
					log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
				}
				log.Info().Str("version", version).NetAddr("address", ln.Addr()).Msg("liner listen and serve dns port")
				go h.ServeTCP(context.Background(), ln)
			case "tls":
				keyfile := &FileLoader[tls.Certificate]{
					Filename:     dns.Keyfile,
					PollDuration: 2 * time.Hour,
					Logger:       log.DefaultLogger.Slog(),
					Unmarshal: func(data []byte, v any) (err error) {
						cert, ok := v.(*tls.Certificate)
						if !ok {
							return errors.New("*tls.Certificate required")
						}
						*cert, err = tls.X509KeyPair(data, data)
						return
					},
				}
				if keyfile.Load() == nil {
					log.Fatal().Str("keyfile", dns.Keyfile).Msg("liner dns load tls keyfile failed")
				}
				ln, err := lc.Listen(context.Background(), "tcp", u.Host)
				if err != nil {
					log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
				}
				ln = tls.NewListener(ln, &tls.Config{
					GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
						return keyfile.Load(), nil
					},
				})
				log.Info().Str("version", version).NetAddr("address", ln.Addr()).Msg("liner listen and serve dns port")
				go h.ServeTCP(context.Background(), ln)
			default:
				log.Fatal().Err(err).Str("address", addr).Msg("dns handler invalid addr error")
			}
		}
	}

	var cronOptions = []cron.Option{
		cron.WithSeconds(),
		cron.WithLogger(cron.PrintfLogger(&log.DefaultLogger)),
	}
	if !config.Global.LogLocaltime {
		cronOptions = append(cronOptions, cron.WithLocation(time.UTC))
	}
	runner := cron.New(cronOptions...)
	if config.Global.LogLevel != "discard" && !log.IsTerminal(os.Stderr.Fd()) {
		runner.AddFunc("0 0 0 * * *", func() { log.DefaultLogger.Writer.(*log.FileWriter).Rotate() })
		if slices.ContainsFunc(config.Http, func(c HTTPConfig) bool { return c.Forward.Log }) ||
			slices.ContainsFunc(config.Https, func(c HTTPConfig) bool { return c.Forward.Log }) ||
			len(config.Dns) > 0 {
			runner.AddFunc("0 0 0 * * *", func() { dataLogger.Writer.(*log.AsyncWriter).Writer.(*log.FileWriter).Rotate() })
		}
	}
	for _, job := range config.Cron {
		spec, command := job.Spec, job.Command
		runner.AddFunc(spec, func() {
			cmd := exec.CommandContext(context.Background(), "/bin/bash", "-c", command)
			if err := cmd.Run(); err != nil {
				log.Warn().Strs("cmd_args", cmd.Args).Err(err).Msg("exec cron_command error")
				return
			}
			log.Info().Str("cron_command", command).Msg("exec cron_command OK")
		})
		log.Info().Str("cron_spec", spec).Str("cron_command", command).Msg("add cron job OK")
	}
	go runner.Run()

	// Set Process Name
	if name := config.Global.SetProcessName; name != "" {
		SetProcessName(name)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, syscall.SIGINT)
	signal.Notify(c, syscall.SIGHUP)

	<-c

	log.Info().Msg("liner flush logs and exit.")
	for _, w := range []log.Writer{
		dataLogger.Writer,
		log.DefaultLogger.Writer,
	} {
		if c, ok := w.(io.Closer); ok {
			c.Close()
		}
	}
	log.Info().Msg("liner server shutdown")
}
