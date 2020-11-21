package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type HTTPConfig struct {
	Listen         []string `json:"listen" yaml:"listen"`
	ServerName     []string `json:"server_name" yaml:"server_name"`
	Keyfile        string   `json:"key_file" yaml:"key_file"`
	Certfile       string   `json:"cert_file" yaml:"cert_file"`
	DisableHttp2   bool     `json:"disable_http2" yaml:"disable_http2"`
	PreferChacha20 bool     `json:"perfer_chacha20" yaml:"perfer_chacha20"`
	Forward        struct {
		Policy       string   `json:"policy" yaml:"policy"`
		Auth         string   `json:"auth" yaml:"auth"`
		Upstream     string   `json:"upstream" yaml:"upstream"`
		AllowDomains []string `json:"allow_domains" yaml:"allow_domains"`
		DenyDomains  []string `json:"deny_domains" yaml:"deny_domains"`
		SpeedLimit   int64    `json:"speed_limit" yaml:"speed_limit"`
		OutboundIp   string   `json:"outbound_ip" yaml:"outbound_ip"`
		Log          bool     `json:"log" yaml:"log"`
	} `json:"forward" yaml:"forward"`
	Pac struct {
		Enabled bool `json:"enabled" yaml:"enabled"`
	} `json:"pac" yaml:"pac"`
	Pprof struct {
		Enabled bool `json:"enabled" yaml:"enabled"`
	} `json:"pprof" yaml:"pprof"`
	Index struct {
		Root    string `json:"root" yaml:"root"`
		Headers string `json:"headers" yaml:"headers"`
		Body    string `json:"body" yaml:"body"`
	} `json:"index" yaml:"index"`
	Proxy struct {
		Pass        string            `json:"pass" yaml:"pass"`
		Headers     map[string]string `json:"headers" yaml:"headers"`
		DumpFailure bool              `json:"dump_failure" yaml:"dump_failure"`
	} `json:"proxy" yaml:"proxy"`
}

type SocksConfig struct {
	Listen  []string `json:"listen" yaml:"listen"`
	Forward struct {
		Policy       string   `json:"policy" yaml:"policy"`
		Auth         string   `json:"auth" yaml:"auth"`
		Upstream     string   `json:"upstream" yaml:"upstream"`
		AllowDomains []string `json:"allow_domain" yaml:"allow_domain"`
		DenyDomains  []string `json:"deny_domains" yaml:"deny_domains"`
		SpeedLimit   int64    `json:"speed_limit" yaml:"speed_limit"`
		OutboundIp   string   `json:"outbound_ip" yaml:"outbound_ip"`
		Log          bool     `json:"log" yaml:"log"`
	} `json:"forward" yaml:"forward"`
}

type RelayConfig struct {
	Listen     []string `json:"listen" yaml:"listen"`
	To         string   `json:"to" yaml:"to"`
	Upstream   string   `json:"upstream" yaml:"upstream"`
	SpeedLimit int64    `json:"speed_limit" yaml:"speed_limit"`
	Log        bool     `json:"log" yaml:"log"`
}

type DNSConfig struct {
	Listen   []string `json:"listen" yaml:"listen"`
	Upstream []string `json:"upstream" yaml:"upstream"`
}

type Config struct {
	raw []byte
	Log struct {
		Level     string `json:"level" yaml:"level"`
		Backups   int    `json:"backups" yaml:"backups"`
		Maxsize   int64  `json:"maxsize" yaml:"maxsize"`
		Localtime bool   `json:"localtime" yaml:"localtime"`
	} `json:"log" yaml:"log"`
	Global struct {
		DenyIntranet    bool   `json:"deny_intranet" yaml:"deny_intranet"`
		DialTimeout     int    `json:"dial_timeout" yaml:"dial_timeout"`
		TcpFastopen     bool   `json:"tcp_fastopen" yaml:"tcp_fastopen"`
		PreferIpv6      bool   `json:"perfer_ipv6" yaml:"perfer_ipv6"`
		DnsServer       string `json:"dns_server" yaml:"dns_server"`
		DnsTtl          uint32 `json:"dns_ttl" yaml:"dns_ttl"`
		IdleConnTimeout int    `json:"idle_conn_timeout" yaml:"idle_conn_timeout"`
		MaxIdleConns    int    `json:"max_idle_conns" yaml:"max_idle_conns"`
		GracefulTimeout int    `json:"graceful_timeout" yaml:"graceful_timeout"`
	} `json:"global" yaml:"global"`
	Cron []struct {
		Spec    string `json:"spec" yaml:"spec"`
		Command string `json:"command" yaml:"command"`
	} `json:"cron" yaml:"cron"`
	Https    []HTTPConfig  `json:"https" yaml:"https"`
	Http     []HTTPConfig  `json:"http" yaml:"http"`
	Socks    []SocksConfig `json:"socks" yaml:"socks"`
	Relay    []RelayConfig `json:"relay" yaml:"relay"`
	Dns      []DNSConfig   `json:"dns" yaml:"dns"`
	Upstream map[string]struct {
		Scheme    string `json:"scheme" yaml:"scheme"`
		Username  string `json:"username" yaml:"username"`
		Password  string `json:"password" yaml:"password"`
		Host      string `json:"host" yaml:"host"`
		Port      int    `json:"port" yaml:"port"`
		UserAgent string `json:"user_agent" yaml:"user_agent"`
	} `json:"upstream" yaml:"upstream"`
}

func NewConfig(filename string) (*Config, error) {
	if filename == "" {
		var env = "development"
		for _, name := range []string{"GOLANG_ENV", "ENV"} {
			if s := os.Getenv(name); s != "" {
				env = s
				break
			}
		}
		for _, ext := range []string{".json", ".yaml"} {
			filename = env + ext
			if _, err := os.Stat(filename); err == nil {
				break
			}
		}
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := new(Config)
	switch filepath.Ext(filename) {
	case ".yaml":
		err = yaml.Unmarshal(data, c)
	case ".json":
		err = json.Unmarshal(data, c)
	default:
		err = fmt.Errorf("format of %s not supportted", filename)
	}
	if err != nil {
		return nil, fmt.Errorf("yaml.Decode(%#v) error: %w", filename, err)
	}

	if filename == "development.yaml" {
		fmt.Fprintf(os.Stderr, "%s WAN 1 config.go:122 > liner is running in the development mode.\n", timeNow().Format("15:04:05"))
	}

	c.raw = data

	return c, nil
}
