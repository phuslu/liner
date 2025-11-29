package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type HTTPConfig struct {
	Listen       []string `json:"listen" yaml:"listen"`
	ServerName   []string `json:"server_name" yaml:"server_name"`
	Keyfile      string   `json:"keyfile" yaml:"keyfile"`
	Certfile     string   `json:"certfile" yaml:"certfile"`
	PSK          string   `json:"psk" yaml:"psk"`
	ServerConfig map[string]struct {
		Keyfile        string `json:"keyfile" yaml:"keyfile"`
		Certfile       string `json:"certfile" yaml:"certfile"`
		DisableHttp2   bool   `json:"disable_http2" yaml:"disable_http2"`
		DisableHttp3   bool   `json:"disable_http3" yaml:"disable_http3"`
		DisableTls11   bool   `json:"disable_tls11" yaml:"disable_tls11"`
		DisableOcsp    bool   `json:"disable_ocsp" yaml:"disable_ocsp"`
		PreferChacha20 bool   `json:"prefer_chacha20" yaml:"prefer_chacha20"`
	} `json:"server_config" yaml:"server_config"`
	Forward struct {
		Policy           string `json:"policy" yaml:"policy"`
		AuthTable        string `json:"auth_table" yaml:"auth_table"`
		Dialer           string `json:"dialer" yaml:"dialer"`
		TcpCongestion    string `json:"tcp_congestion" yaml:"tcp_congestion"`
		DenyDomainsTable string `json:"deny_domains_table" yaml:"deny_domains_table"`
		SpeedLimit       int64  `json:"speed_limit" yaml:"speed_limit"`
		DisableIpv6      bool   `json:"disable_ipv6" yaml:"disable_ipv6"`
		PreferIpv6       bool   `json:"prefer_ipv6" yaml:"prefer_ipv6"`
		Log              bool   `json:"log" yaml:"log"`
		LogInterval      int64  `json:"log_interval" yaml:"log_interval"`
		IoCopyBuffer     int    `json:"io_copy_buffer" yaml:"io_copy_buffer"`
		IdleTimeout      int64  `json:"idle_timeout" yaml:"idle_timeout"`
	} `json:"forward" yaml:"forward"`
	Tunnel struct {
		Enabled         bool     `json:"enabled" yaml:"enabled"`
		AuthTable       string   `json:"auth_table" yaml:"auth_table"`
		AllowListens    []string `json:"allow_listens" yaml:"allow_listens"`
		SpeedLimit      int64    `json:"speed_limit" yaml:"speed_limit"`
		EnableKeepAlive bool     `json:"enable_keep_alive" yaml:"enable_keep_alive"`
		Log             bool     `json:"log" yaml:"log"`
	} `json:"tunnel" yaml:"tunnel"`
	Web []struct {
		Location      string `json:"location" yaml:"location"`
		TcpCongestion string `json:"tcp_congestion" yaml:"tcp_congestion"`
		Fastcgi       struct {
			Enabled    bool   `json:"enabled" yaml:"enabled"`
			Root       string `json:"root" yaml:"root"`
			DefaultAPP string `json:"default_app" yaml:"default_app"`
		} `json:"fastcgi" yaml:"fastcgi"`
		Dav struct {
			Enabled   bool   `json:"enabled" yaml:"enabled"`
			Root      string `json:"root" yaml:"root"`
			AuthTable string `json:"auth_table" yaml:"auth_table"`
		} `json:"dav" yaml:"dav"`
		Doh struct {
			Enabled   bool   `json:"enabled" yaml:"enabled"`
			Policy    string `json:"policy" yaml:"policy"`
			ProxyPass string `json:"proxy_pass" yaml:"proxy_pass"`
			CacheSize int    `json:"cache_size" yaml:"cache_size"`
		} `json:"doh" yaml:"doh"`
		Index struct {
			Root    string `json:"root" yaml:"root"`
			Headers string `json:"headers" yaml:"headers"`
			Charset string `json:"charset" yaml:"charset"`
			Body    string `json:"body" yaml:"body"`
			File    string `json:"file" yaml:"file"`
		} `json:"index" yaml:"index"`
		Proxy struct {
			Pass        string `json:"pass" yaml:"pass"`
			AuthTable   string `json:"auth_table" yaml:"auth_table"`
			StripPrefix string `json:"strip_prefix" yaml:"strip_prefix"`
			SetHeaders  string `json:"set_headers" yaml:"set_headers"`
			DumpFailure bool   `json:"dump_failure" yaml:"dump_failure"`
		} `json:"proxy" yaml:"proxy"`
	} `json:"web" yaml:"web"`
}

type SniConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Policy  string `json:"policy" yaml:"policy"`
	Log     bool   `json:"log" yaml:"log"`
}

type SocksConfig struct {
	Listen  []string `json:"listen" yaml:"listen"`
	PSK     string   `json:"psk" yaml:"psk"`
	Forward struct {
		Policy           string `json:"policy" yaml:"policy"`
		AuthTable        string `json:"auth_table" yaml:"auth_table"`
		Dialer           string `json:"dialer" yaml:"dialer"`
		DenyDomainsTable string `json:"deny_domains_table" yaml:"deny_domains_table"`
		SpeedLimit       int64  `json:"speed_limit" yaml:"speed_limit"`
		DisableIpv6      bool   `json:"disable_ipv6" yaml:"disable_ipv6"`
		PreferIpv6       bool   `json:"prefer_ipv6" yaml:"prefer_ipv6"`
		Log              bool   `json:"log" yaml:"log"`
	} `json:"forward" yaml:"forward"`
}

type RedsocksConfig struct {
	Listen  []string `json:"listen" yaml:"listen"`
	Forward struct {
		Dialer string `json:"dialer" yaml:"dialer"`
		Log    bool   `json:"log" yaml:"log"`
	} `json:"forward" yaml:"forward"`
}

type StreamConfig struct {
	Listen        []string `json:"listen" yaml:"listen"`
	Keyfile       string   `json:"keyfile" yaml:"keyfile"`
	Certfile      string   `json:"certfile" yaml:"certfile"`
	ProxyPass     string   `json:"proxy_pass" yaml:"proxy_pass"`
	ProxyProtocol uint     `json:"proxy_protocol" yaml:"proxy_protocol"`
	DialTimeout   int      `json:"dial_timeout" yaml:"dial_timeout"`
	Dialer        string   `json:"dialer" yaml:"dialer"`
	SpeedLimit    int64    `json:"speed_limit" yaml:"speed_limit"`
	Log           bool     `json:"log" yaml:"log"`
}

type TunnelConfig struct {
	RemoteListen    []string `json:"remote_listen" yaml:"remote_listen"`
	ProxyPass       string   `json:"proxy_pass" yaml:"proxy_pass"`
	Resolver        string   `json:"resolver" yaml:"resolver"`
	DialTimeout     int      `json:"dial_timeout" yaml:"dial_timeout"`
	Dialer          string   `json:"dialer" yaml:"dialer"`
	SpeedLimit      int64    `json:"speed_limit" yaml:"speed_limit"`
	EnableKeepAlive bool     `json:"enable_keep_alive" yaml:"enable_keep_alive"`
	Log             bool     `json:"log" yaml:"log"`
}

type DnsConfig struct {
	Listen    []string `json:"listen" yaml:"listen"`
	Keyfile   string   `json:"keyfile" yaml:"keyfile"`
	Policy    string   `json:"policy" yaml:"policy"`
	ProxyPass string   `json:"proxy_pass" yaml:"proxy_pass"`
	CacheSize int      `json:"cache_size" yaml:"cache_size"`
	Log       bool     `json:"log" yaml:"log"`
}

type SshConfig struct {
	Listen           []string `json:"listen" yaml:"listen"`
	ServerVersion    string   `json:"server_version" yaml:"server_version"`
	TcpReadBuffer    int      `json:"tcp_read_buffer" yaml:"tcp_read_buffer"`
	TcpWriteBuffer   int      `json:"tcp_write_buffer" yaml:"tcp_write_buffer"`
	DisableKeepalive bool     `json:"disable_keepalive" yaml:"disable_keepalive"`
	BannerFile       string   `json:"banner_file" yaml:"banner_file"`
	HostKey          string   `json:"host_key" yaml:"host_key"`
	AuthTable        string   `json:"auth_table" yaml:"auth_table"`
	AuthorizedKeys   string   `json:"authorized_keys" yaml:"authorized_keys"`
	Shell            string   `json:"shell" yaml:"shell"`
	Home             string   `json:"home" yaml:"home"`
	EnvFile          string   `json:"env_file" yaml:"env_file"`
	Log              bool     `json:"log" yaml:"log"`
}

type Config struct {
	Global struct {
		LogDir           string `json:"log_dir" yaml:"log_dir"`
		LogLevel         string `json:"log_level" yaml:"log_level"`
		LogBackups       int    `json:"log_backups" yaml:"log_backups"`
		LogMaxsize       int64  `json:"log_maxsize" yaml:"log_maxsize"`
		LogLocaltime     bool   `json:"log_localtime" yaml:"log_localtime"`
		LogChannelSize   uint   `json:"log_channel_size" yaml:"log_channel_size"`
		ForbidLocalAddr  bool   `json:"forbid_local_addr" yaml:"forbid_local_addr"`
		DialTimeout      int    `json:"dial_timeout" yaml:"dial_timeout"`
		DialReadBuffer   int    `json:"dial_read_buffer" yaml:"dial_read_buffer"` // Danger, see https://issues.apache.org/jira/browse/KAFKA-16496
		DialWriteBuffer  int    `json:"dial_write_buffer" yaml:"dial_write_buffer"`
		DnsServer        string `json:"dns_server" yaml:"dns_server"`
		DnsCacheDuration string `json:"dns_cache_duration" yaml:"dns_cache_duration"`
		DnsCacheSize     int    `json:"dns_cache_size" yaml:"dns_cache_size"`
		TcpReadBuffer    int    `json:"tcp_read_buffer" yaml:"tcp_read_buffer"`
		TcpWriteBuffer   int    `json:"tcp_write_buffer" yaml:"tcp_write_buffer"`
		TlsInsecure      bool   `json:"tls_insecure" yaml:"tls_insecure"`
		AutocertDir      string `json:"autocert_dir" yaml:"autocert_dir"`
		GeoipDir         string `json:"geoip_dir" yaml:"geoip_dir"`
		GeoipCacheSize   int    `json:"geoip_cache_size" yaml:"geoip_cache_size"`
		GeositeDisabled  bool   `json:"geosite_disabled" yaml:"geosite_disabled"`
		GeositeCacheSize int    `json:"geosite_cache_size" yaml:"geosite_cache_size"`
		IdleConnTimeout  int    `json:"idle_conn_timeout" yaml:"idle_conn_timeout"`
		MaxIdleConns     int    `json:"max_idle_conns" yaml:"max_idle_conns"`
		DisableHttp3     bool   `json:"disable_http3" yaml:"disable_http3"`
		SetProcessName   string `json:"set_process_name" yaml:"set_process_name"`
	} `json:"global" yaml:"global"`
	Cron []struct {
		Spec    string `json:"spec" yaml:"spec"`
		Command string `json:"command" yaml:"command"`
	} `json:"cron" yaml:"cron"`
	Dialer   map[string]string `json:"dialer" yaml:"dialer"`
	Sni      SniConfig         `json:"sni" yaml:"sni"`
	Https    []HTTPConfig      `json:"https" yaml:"https"`
	Http     []HTTPConfig      `json:"http" yaml:"http"`
	Socks    []SocksConfig     `json:"socks" yaml:"socks"`
	Redsocks []RedsocksConfig  `json:"redsocks" yaml:"redsocks"`
	Tunnel   []TunnelConfig    `json:"tunnel" yaml:"tunnel"`
	Stream   []StreamConfig    `json:"stream" yaml:"stream"`
	Ssh      []SshConfig       `json:"ssh" yaml:"ssh"`
	Dns      []DnsConfig       `json:"dns" yaml:"dns"`
}

func NewConfig(filename string) (*Config, error) {
	datas := [][]byte{}
	if data, err := ReadFile(filename); err == nil {
		datas = append(datas, data)
	} else {
		return nil, err
	}

	if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".json") {
		dir, ext := filename[:len(filename)-len(filepath.Ext(filename))]+".d", filepath.Ext(filename)
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if name := entry.Name(); strings.HasSuffix(name, ext) {
					if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
						datas = append(datas, data)
					}
				}
			}
		}
	}

	configs := []*Config{}
	for _, data := range datas {
		c := new(Config)
		var err error
		switch {
		case strings.HasSuffix(filename, ".yaml"):
			err = yaml.Unmarshal(data, c)
		case strings.HasSuffix(filename, ".json"):
			err = json.Unmarshal(data, c)
		case filename == "-":
			if strings.HasPrefix(b2s(data), "{") {
				err = json.Unmarshal(data, c)
			} else {
				err = yaml.Unmarshal(data, c)
			}
		default:
			err = fmt.Errorf("format of %s not supportted", filename)
		}
		if err != nil {
			return nil, fmt.Errorf("yaml.Decode(%#v) error: %w", filename, err)
		}
		configs = append(configs, c)
	}

	config := configs[0]
	for _, c := range configs[1:] {
		config.Cron = append(config.Cron, c.Cron...)
		for key, value := range c.Dialer {
			if config.Dialer == nil {
				config.Dialer = make(map[string]string)
			}
			config.Dialer[key] = value
		}
		config.Https = append(config.Https, c.Https...)
		config.Http = append(config.Http, c.Http...)
		config.Socks = append(config.Socks, c.Socks...)
		config.Tunnel = append(config.Tunnel, c.Tunnel...)
		config.Stream = append(config.Stream, c.Stream...)
		config.Dns = append(config.Dns, c.Dns...)
		config.Ssh = append(config.Ssh, c.Ssh...)
	}

	read := func(s string) string {
		if !strings.HasPrefix(s, "@") {
			return s
		}
		data, err := os.ReadFile(s[1:])
		if err != nil {
			panic(err)
		}
		return string(data)
	}

	for i := range config.Http {
		config.Http[i].Forward.Policy = read(config.Http[i].Forward.Policy)
		config.Http[i].Forward.Dialer = read(config.Http[i].Forward.Dialer)
		config.Http[i].Forward.TcpCongestion = read(config.Http[i].Forward.TcpCongestion)
		for j := range config.Http[i].Web {
			config.Http[i].Web[j].Index.Headers = read(config.Http[i].Web[j].Index.Headers)
			config.Http[i].Web[j].Index.Body = read(config.Http[i].Web[j].Index.Body)
			config.Http[i].Web[j].Proxy.Pass = read(config.Http[i].Web[j].Proxy.Pass)
			config.Http[i].Web[j].Proxy.SetHeaders = read(config.Http[i].Web[j].Proxy.SetHeaders)
		}
	}
	for i := range config.Https {
		config.Https[i].Forward.Policy = read(config.Https[i].Forward.Policy)
		config.Https[i].Forward.Dialer = read(config.Https[i].Forward.Dialer)
		config.Https[i].Forward.TcpCongestion = read(config.Https[i].Forward.TcpCongestion)
		for j := range config.Https[i].Web {
			config.Https[i].Web[j].Index.Headers = read(config.Https[i].Web[j].Index.Headers)
			config.Https[i].Web[j].Index.Body = read(config.Https[i].Web[j].Index.Body)
			config.Https[i].Web[j].Proxy.Pass = read(config.Https[i].Web[j].Proxy.Pass)
			config.Https[i].Web[j].Proxy.SetHeaders = read(config.Https[i].Web[j].Proxy.SetHeaders)
		}
	}
	for i := range config.Socks {
		config.Socks[i].Forward.Policy = read(config.Socks[i].Forward.Policy)
		config.Socks[i].Forward.Dialer = read(config.Socks[i].Forward.Dialer)
	}
	for i := range config.Tunnel {
		if len(config.Tunnel[i].RemoteListen) != 1 && config.Tunnel[i].RemoteListen[0] == "" {
			return nil, fmt.Errorf("invalid tunnel remote_listen=%v", config.Tunnel[i].RemoteListen)
		}
	}

	if filename == "development.yaml" {
		fmt.Fprintf(os.Stderr, "%s WAN 1 config.go:122 > liner is running in the development mode.\n", timeNow().Format("15:04:05"))
	}

	for _, server := range config.Https {
		if server.PSK != "" {
			return nil, fmt.Errorf("invalid psk option in https handler: server_name=%#v, psk=%#v", server.ServerName, server.PSK)
		}
	}

	return config, nil
}
