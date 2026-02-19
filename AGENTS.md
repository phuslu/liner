# Liner - Agent Instructions

## Project Overview
Liner is a high-performance, modular network proxy and tunneling tool developed in Go.
- **Language**: Go 1.26+
- **Architecture**: Modular Listen → Handle → Dial pipeline with pluggable building blocks
- **Core Features**: HTTP/HTTPS/SOCKS5 proxy, tunnel service (client & server), DNS service (UDP/TCP/DoT/DoH/DoQ), SSH server, SNI routing, GeoIP/GeoSite aware traffic splitting, memory listeners for zero-copy hops, real-time log tailing

## Core Architecture Concepts

### Three-Tier Architecture Pattern
Liner's core workflow follows the **Listen -> Handle -> Dial** design pattern:

```
[Client Request]
    ↓
[Listeners] → Accept connections
    ↓
[Handlers] → Business logic, routing decisions
    ↓
[Dialers] → Establish upstream connections
    ↓
[Target Server]
```

### Core Design Principles
1. **Modularity**: Each protocol or feature is encapsulated in a dedicated handler/dialer with shared helpers
2. **Extensibility**: Configuration wires listeners, handlers, dialers, and policy templates to form arbitrary proxy chains
3. **Performance First**: Parallel dialing, memory listeners, ring-buffer log fan-out, TLS/session caches
4. **Intelligent Routing**: GeoIP/GeoSite/policy templates steer traffic per request metadata

## Key Terms and Concepts

### Listeners
Responsible for accepting client connections on configured ports or in-memory endpoints:
- **HTTP/HTTPS**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC) with autocert, custom certificates, per-server TLS toggles and optional PSK wrapping
- **SOCKS5**: SOCKS proxy (TCP), supports username/password, CSV/JSON/command auth tables, PSK transport encryption
- **SSH**: Full SSH server with shell, SFTP, remote command execution and port forwarding
- **DNS**: UDP, TCP, DoT, DoH/DoH3 (quic-go) frontends with caching and policy routing
- **Stream**: Generic TCP/PSK ingress for port forwarding or proxy protocol targets
- **Tunnel**: Intranet penetration listener plus remote tunnel clients (HTTP/1/2/3/WebSocket/SSH) using yamux/smux multiplexers
- **Redsocks**: Transparent TCP proxy (Linux only) for iptables-based interception
- **MemoryListener**: In-process listener bound to reserved `240.0.0.0/8` addresses for zero-copy wiring between modules

### Handlers
Contain business logic, routing and protocol-specific behavior:
- **HTTPForwardHandler**: HTTP forward proxy (CONNECT & plaintext), deny-list enforcement, per-user speed limits, auth, TCP congestion hints, per-request dialer selection & logging
- **HTTPWebHandler**: Hosts multiple sub-handlers such as static index pages, WebDAV, DoH, reverse proxy, WebShell, and Logtail SSE streaming
  - `handler_http_web_index.go`: Static file/directory serving with templated headers/body
  - `handler_http_web_dav.go`: WebDAV with AuthUser integration
  - `handler_http_web_doh.go`: DNS-over-HTTPS resolver backed by fastdns caches
  - `handler_http_web_proxy.go`: Reverse proxy with header rewriting and failure dumps
  - `handler_http_web_shell.go`: PTY-backed shell sharing, templated prompts, per-user quotas
  - `handler_http_web_logtail.go`: Real-time log streaming sourced from the ring buffer (requires `allow_logtail` attribute)
- **HTTPTunnelHandler**: HTTP tunnel protocol, access control via `auth_table`, listen allowlists and connection logging
- **SocksHandler**: Implements SOCKS5 handshake, UDP associate, auth, deny domains, IPv6 preferences
- **SniHandler**: TLS SNI splitter selecting policies/dialers by template decisions
- **StreamHandler**: Plain TCP port forwarding with optional TLS/PSK and Proxy Protocol parsing
- **SshHandler**: SSH server (host keys, autocert-like banners, authorized_keys, PTY, SFTP, QUIC multiplexing, env injection)
- **DnsHandler**: DNS policy engine with template-based routing, logging, UDP/TCP/DoT/DoH handling and caching via fastdns
- **RedsocksHandler**: Transparent proxy bridging intercepted TCP to configured dialers
- **TunnelHandler** (`handler_tunnel*.go`): Remote tunnel client orchestrating HTTP/1.1, HTTP/2, HTTP/3, SSH multiplexed listeners and MemoryListener hand-offs

### Dialers
Establish upstream connections, optionally chaining through other dialers:
- **LocalDialer** (`dialer_local.go`): Direct socket dialing with interface binding, IPv4/IPv6 preference toggles, per-request overrides, DNS resolver integration, parallel dialing and optional TLS client config
- **HTTPDialer/HTTP2Dialer/HTTP3Dialer**: Forward requests via HTTP/1.1, HTTP/2 or HTTP/3 proxies, support websocket upgrades, header injection, PSK encryption, JA4/TLS fingerprint shaping
- **SocksDialer**: SOCKS4/SOCKS5 upstream with username/password or PSK, UDP associate, chained authentication
- **SSHDialer**: Establishes yamux/smux sessions over SSH tunnels with keepalive controls
- **MemoryDialer**: In-memory net.Conn provider tied to MemoryListener addresses, bypassing kernel networking for tunnels and SSH subsystems
- **Dialer Chain**: Multi-line `dialer.proxy_chain` config composes dialers from bottom to top (e.g., local → SOCKS → SSH → HTTP3)

### Core Utility Components

#### DnsResolverPool (`resolver_dns.go`)
- Builds fastdns clients for UDP, TCP, DoT, DoH/DoH3 endpoints with TLS session caches
- Shares LRU caches across handlers with per-address TTLs
- Honors global IPv6 disablement, DoH user-agent overrides and HTTP3 transports

#### GeoResolver (Geolocation Resolver, `resolver_geo.go`)
- Integrates MaxMind GeoIP (country/city/ASN) and GeoSite domain DBs with template helpers and LRU caches
- Provides DNS resolution helpers and IPv4/IPv6 aware memory dialers

#### TLSInspector (`tls.go`)
- Extracts JA4 fingerprints, inspects TLS ClientHello, handles autocert, multi-cert SNI routing and lets handlers emulate browser stacks

#### Functions (`functions.go`)
- Template helper library for policies (GeoIP/GeoSite checks, header matching, regex, file reads, HTTP fetches, DNS lookups)
- Results cached where safe to avoid recomputation

## Directory Structure

```
liner/
├── main.go                         # Program entry, service bootstrap, logging, cron, MCP server
├── config.go                       # Configuration schema, loaders (.d overlay, @file support)
├── dialer.go                       # Dialer interface, memory dialers/listeners
├── dialer_local.go                 # LocalDialer implementation and racing logic
├── dialer_http.go                  # HTTP/1.1 + WebSocket dialer with PSK support
├── dialer_http2.go                 # HTTP/2 dialer
├── dialer_http3.go                 # HTTP/3/QUIC dialer
├── dialer_socks.go                 # SOCKS4/SOCKS5 dialer with PSK
├── dialer_ssh.go                   # SSH dialer (yamux/smux muxers)
├── handler_http.go                 # HTTP multiplexer (Forward/Tunnel/Web)
├── handler_http_forward.go         # HTTP forward proxy logic
├── handler_http_tunnel.go          # HTTP tunnel protocol handler
├── handler_http_web.go             # Web handler dispatcher
├── handler_http_web_dav.go         # WebDAV implementation
├── handler_http_web_doh.go         # DNS over HTTPS service
├── handler_http_web_index.go       # Static file/directory server
├── handler_http_web_logtail.go     # Logtail streaming
├── handler_http_web_proxy.go       # Reverse proxy
├── handler_http_web_shell.go       # WebShell + PTY management
├── handler_dns.go                  # DNS server handler
├── handler_redsocks.go             # Redsocks transparent proxy
├── handler_sni.go                  # TLS SNI router
├── handler_socks.go                # SOCKS5 handler
├── handler_stream.go               # Generic port forwarding handler
├── handler_ssh.go                  # SSH server handler
├── handler_tunnel.go               # Tunnel client orchestrator
├── handler_tunnel_http.go          # HTTP/1.1 tunnel transport
├── handler_tunnel_http2.go         # HTTP/2 tunnel transport
├── handler_tunnel_http3.go         # HTTP/3/QUIC tunnel transport
├── handler_tunnel_ssh.go           # SSH tunnel transport
├── resolver_dns.go                 # DNS resolver pool + caching
├── resolver_geo.go                 # GeoIP/GeoSite resolver
├── resolver_getter.go              # DNS resolver getter helpers
├── tls.go                          # TLS inspection, autocert, JA4
├── functions.go                    # Template functions
├── auth_user.go                    # Auth table loaders/checkers (file/command/hash)
├── helpers.go                      # Networking helpers, MemoryListener, listener factory
├── helpers_linux.go / helpers_others.go  # Platform-specific helpers
├── mime_types.go                   # MIME DB for static serving
└── x509.go                         # X.509 certificate utilities
```

## Code Patterns and Conventions

### Configuration Loading Pattern
```go
// All handlers implement the Load() method for initialization
type HTTPHandler interface {
    Load() error
    ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// Configuration files support YAML/JSON and `.d` overlay directories
config, err := NewConfig("config.yaml")
// Strings beginning with '@' are treated as file includes for policies, headers, etc.
```

### Dialer Interface Specification
```go
type Dialer interface {
    DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Dialer chain composition
underlay := &LocalDialer{DnsResolver: resolver, Interface: "eth0"}
proxy := &SocksDialer{Dialer: underlay, AuthUser: "foo", AuthPassword: "bar"}
conn, err := proxy.DialContext(ctx, "tcp", "example.com:443")
```

### Context Keys
```go
var (
    DialerHTTPHeaderContextKey      any = &DialerContextKey{"dailer-http-header"}
    DialerDisableIPv6ContextKey     any = &DialerContextKey{"dailer-disable-ipv6"}
    DialerPreferIPv6ContextKey      any = &DialerContextKey{"dailer-prefer-ipv6"}
    DialerMemoryDialersContextKey   any = &DialerContextKey{"dailer-memory-dialers"}
    DialerMemoryListenersContextKey any = &DialerContextKey{"dailer-memory-listeners"}
)

ctx = context.WithValue(ctx, DialerDisableIPv6ContextKey, true)
conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
```

### Memory Dialers / Listeners
```go
mds := &MemoryDialers{xsync.NewMap[string, *MemoryDialer]()}
ctx = MemoryDialersWith(ctx, mds)
md := &MemoryDialer{Address: "240.1.1.1:10000", Session: muxSession}
mds.Store(md.Address, md)
```
This allows TunnelHandler and LocalDialer to exchange in-process connections without touching the OS stack (`MemoryDialerIPPrefix` = `240.0.0.0/8`).

### Error Handling
```go
if err != nil {
    log.Error().Err(err).Str("address", addr).Msg("description")
    return fmt.Errorf("operation failed: %w", err)
}
```

## Common Operation Scenarios

### Adding a New Dialer
1. Create `dialer_<protocol>.go` in the root directory
2. Implement the `Dialer` (and optional TLS) interface
3. Register URL scheme handling in `dialerof`/`main.go` so configs can reference it
4. Document configuration syntax and options

### Adding a New Handler
1. Create `handler_<feature>.go`
2. Implement `Load()` (for validation, auth table loading, templating) and serving logic
3. Register it in `main.go` alongside required listeners/dialers
4. Update `Config` structs in `config.go` and sample configs

### Adding Routing Policy
1. Extend `functions.go` with new template helpers
2. Reference functions inside `policy`/`forward.policy` fields
3. Policies can inspect GeoIP, GeoSite, request headers, user attributes, JA4, etc.

### Configuration Examples

#### HTTP Proxy Configuration
```yaml
http:
  - listen:
      - "0.0.0.0:8080"
    forward:
      policy: "direct"  # Or template, e.g. {{ if geoip_cn .RemoteAddr }}direct{{ else }}proxy{{ end }}
      dialer: "local"
      deny_domains_table: "@deny_domains.txt"
```

#### SOCKS5 Proxy Configuration
```yaml
socks:
  - listen:
      - "0.0.0.0:1080"
    psk: "3xamplePSK"         # Optional ChaCha20 layer
    auth_table: "authuser.csv"
    forward:
      dialer: "local"
      policy: "direct"
```

#### Intranet Penetration Configuration
```yaml
tunnel:
  - role: server
    listen:
      - "0.0.0.0:4433"
    server_name: "tunnel.example.com"
    keyfile: "/path/to/key.pem"
    psks:
      - "shared-secret"
```

#### SNI Routing Configuration
```yaml
sni:
  enabled: true
  forward:
    policy: |
      {{ if geosite_cn .SNI }}direct{{ else }}proxy{{ end }}
    dialer: "local"
    log: true
```

## Performance Optimization Features

### Connection Management
- LocalDialer parallel dials across IPv4/IPv6 with configurable concurrency, keepalives and interface binding
- TCP Keep-Alive defaults to 30s, tunable per listener
- MemoryDialer/MemoryListener pairs bypass kernel networking for tunnels/SSH/streams
- HTTP/2, HTTP/3 and SSH dialers reuse mux sessions for thousands of streams

### Caching Mechanisms
- DNS query caching via `fastdns` + TTL LRU caches sharing across resolvers
- GeoIP/GeoSite caches (LRU with configurable sizes)
- TLS ClientHello fingerprint cache, TLS session cache, template function memoization
- Ring buffer backed log broadcaster feeding HTTP logtail without disk seeks

### Concurrency Control
- Goroutine pools and context cancellation to avoid leaks
- Concurrent DNS resolution for IPv4/IPv6 answers
- Rate limiting hooks (`speed_limit`, `request`, `stream`) enforced via user attributes and handler config

### Zero-Copy Optimization
- `io.Copy` streaming for TCP forwarding, optional buffer sizing via config
- MemoryListener/MemoryDialer to avoid kernel loops between tunnel entry and internal handlers
- Configurable TCP congestion algorithms per forward proxy

## Important Configuration Items

### Global Configuration
- Logging: `log_dir`, `log_level`, `log_backups`, `log_maxsize`, `log_localtime`, `log_channel_size` control stdout file/async writers feeding the logtail ring buffer
- Networking: `forbid_local_addr`, `dial_timeout`, `dial_read_buffer`, `dial_write_buffer`, `tcp_read_buffer`, `tcp_write_buffer`, `idle_conn_timeout`, `max_idle_conns`
- DNS: `dns_server` (supports `udp://`, `tcp://`, `dot://`, `https://`, `http3://`), `dns_cache_duration`, `dns_cache_size`
- TLS & Certificates: `tls_insecure`, `autocert_dir`, `disable_http3`, plus HTTP server-specific `server_config`
- Geo: `geoip_dir`, `geoip_cache_size`, `geosite_cache_size`, `disable_geosite`
- Misc: `set_process_name` (rename process), `cron` array (`spec`, `command`) executed via embedded gosh shell

### Dialer Configuration
Supports multi-line configuration where each line is one proxy layer (built bottom-up):
```yaml
dialer:
  proxy_chain: |
    local://eth0?disable_ipv6=1
    socks5://user:pass@proxy1.com:1080
    ssh://user@proxy2.com:22?key=/path/to/key&keepalive=10s
    http3://proxy3.example.com:7443?ja4=chrome&psk=secret
```
Additional per-dialer knobs (time outs, headers, JA4/TLS fingerprints) live inside each scheme's query params.

### HTTP/HTTPS Configuration
- Listener security: `psk` (ChaCha20 overlay), `server_config` toggles (disable HTTP/2/3/TLS1.1, prefer ChaCha20, OCSP)
- Forward proxy: `policy`, `auth_table`, `dialer`, `tcp_congestion`, `deny_domains_table`, `speed_limit`, IPv6 toggles, `log`, `io_copy_buffer`, `idle_timeout`
- Tunnel sub-block: enable per-listen tunnels, `auth_table`, `allow_listens`, `disable_keepalive`
- Web sub-handlers: `forward_auth`, `dav`, `doh`, `index`, `proxy`, `shell` (command, home, template), `logtail` (requires `allow_logtail=1` attribute)

### SOCKS / Stream / Tunnel / SNI / DNS / SSH
- **SOCKS**: `psk`, `auth_table`, `deny_domains_table`, IPv6 preferences, speed limits
- **Stream**: `proxy_protocol`, TLS/PSK, `dialer`, `dial_timeout`, `speed_limit`, logging
- **Tunnel**: `remote_listen`, `proxy_pass`, `resolver`, `dial_timeout`, `dialer`, `disable_keepalive`, `log`
- **SNI**: template-driven routing with IPv6 toggles, logging, dialer reference
- **DNS**: `listen`, optional TLS key pair, `policy`, `proxy_pass`, `cache_size`, `log`
- **SSH**: `listen`, `server_version`, TCP buffers, keepalive toggle, `banner_file` (Go template), `host_key`, `auth_table`, `authorized_keys`, `shell`, `home`, `env_file`, `log`

### Authentication Configuration
- `auth_table` accepts inline `user:pass`, CSV/JSON files, or external commands (detected automatically); also supports `file:///` URIs via shell quoting
- Passwords may be stored plaintext, hex (`0x` prefixed) MD5/SHA1/SHA256, bcrypt (`$2y$`), or argon2id
- Command-based loaders/checkers can return JSON attributes; attributes such as `speed_limit`, `allow_tunnel`, `allow_client`, `allow_webdav`, `allow_logtail`, `allow_ssh` drive handler decisions

## Debugging and Testing

### Logging System
- Main log + data log + error log with rotation; logs are mirrored into an in-memory ring buffer consumed by `web.logtail`
- Configure `log_channel_size` to avoid dropping events; set `log_level: discard` for silent runs
- Trace IDs are attached to DNS/HTTP handlers to correlate events in logs

### Testing Commands
```bash
# Run all tests
go test ./...

# Run specific test
go test -v -run TestResolverLookup

# Build
go build -v

# Build with version information
go build -ldflags "-X main.version=$(git describe --tags)"
```

## Extension and Integration

### MCP Server Integration
The project exposes MCP server commands for config management:
- `generate_liner_config` – produce a comprehensive config
- `generate_http_config` – HTTP module helper
- `generate_dialer_config` – compose proxy chains
- `validate_liner_config` – structural validation
See `.mcp.json` for transport details.

### Third-Party Library Dependencies
- `github.com/phuslu/log` – structured logging
- `github.com/phuslu/fastdns` – DNS protocol stack, DoH/DoQ transports
- `github.com/phuslu/geosite`, `github.com/oschwald/maxminddb-golang/v2` – GeoIP/GeoSite DBs
- `github.com/puzpuzpuz/xsync/v4` – concurrent maps for dialers, auth tables, logtail clients
- `github.com/quic-go/quic-go`, `github.com/quic-go/quic-go/http3` – HTTP/3/QUIC transports
- `github.com/libp2p/go-yamux/v5`, `github.com/xtaci/smux` – tunnel/SSH multiplexers
- `github.com/refraction-networking/utls` – JA4/TLS fingerprint shaping
- `github.com/mileusna/useragent` – UA parsing for policy templates
- `github.com/robfig/cron/v3` – Cron scheduler for background commands
- `github.com/smallnest/ringbuffer` – in-memory log broadcaster

## Common Issues and Notes

### Certificate Management
- HTTPS listeners support manual key/cert, autocert, multi-cert `server_config` entries
- TLS inspector can auto-select certs per SNI and emulate browser JA4 strings; PSK overlays (ChaCha20) require matching keys on dialers/listeners

### Memory Listener
- Reserved IP range `240.0.0.0/8` is used for MemoryDialer/MemoryListener pairs
- Tunnel/SSH modules inject connections directly into MemoryListener queues, so ensure address uniqueness per module

### IPv6 Support
- IPv4/IPv6 handled concurrently; `disable_ipv6`, `prefer_ipv6` flags exist globally and per-forward/policy context
- LocalDialer falls back between address families based on error heuristics

### Transparent Proxy
- Redsocks requires Linux (uses iptables + transparent sockets)
- SNI handler can steer TLS connections based solely on SNI without decrypting traffic

### Authentication Tables
- Ensure CSV headers include attribute names required by handlers (e.g., `allow_client`, `speed_limit`)
- Web logtail demands `allow_logtail=1`; WebDAV/SSH/tunnel respect their respective `allow_*` flags

## Development Guide

### Steps to Add New Features
1. Study similar modules (e.g., HTTP tunnel vs. SSH tunnel) for patterns (Load, Serve, logging)
2. Name files `handler_<feature>.go` or `dialer_<protocol>.go`
3. Update `config.go` structs and `NewConfig` merging logic
4. Register new components in `main.go` (listener setup, goroutines, signal handling)
5. Document config usage (AGENTS.md/README/tests) and provide sample YAML entries
6. Add tests (unit or integration) and run `go test ./...`

### Code Style
- Go 1.26 module, enforce `gofmt`
- Explicit error handling (no ignored returns)
- Exported types/functions require comments
- Prefer standard lib or existing vendored deps

### Performance Considerations
- Avoid per-request allocations; reuse buffers and `sync.Pool` (see DNS handler)
- Guard against goroutine leaks via context cancellation and deadline propagation
- Use streaming (`io.Copy`) for large transfers, tune buffers via config
- Use `context` to propagate auth, dialer hints, logging metadata

## Related Files
- Configuration examples: `*.yaml` in project root (`example.yaml`, `test.yaml`, `phuslu.yaml`)
- Build scripts: `build.bash`, `make.bash`
- CLI helper: `gosh.go` (embedded shell used by cron/autop commands)
