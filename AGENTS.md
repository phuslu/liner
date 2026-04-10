# Liner - Agent Instructions

## Project Overview
Liner is a high-performance, modular network proxy and tunneling tool developed in Go.
- **Language**: Go 1.26+
- **Architecture**: Modular Listen → Handle → Dial pipeline with pluggable building blocks
- **Core Features**: HTTP/HTTPS/SOCKS5 proxies (including MASQUE-style HTTP tunnels), tunnel service (client & server), DNS service (UDP/TCP/DoT/DoH/DoH3), SSH server, SNI routing, Redsocks/Stream forwarding, GeoIP/GeoSite aware traffic splitting, memory listeners for zero-copy hops, real-time log tailing

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

## Runtime Behavior & Tooling
- Configuration selection follows `ENV=<name>` → `<name>.yaml`, explicit CLI arguments, then stdin (`-`). Files may be YAML or JSON, strings beginning with `https://` are fetched via the helper `ReadFile`, and `.d` overlay directories plus `@file` references are merged automatically.
- Launching with `GOSH=1` runs the interactive shell in `gosh.go` (mvdan/sh parser, readline history, completion, `GOSH_ENV` profile sourcing, non-interactive script support). SSH shells can re-enter `liner` by setting `shell: "$"` which spawns the same binary with `GOSH=1`.
- `global.cron` jobs render their `command` through the template engine (so template functions and config state can be used) and execute the resulting string via `/bin/bash -c`. Standard logging captures successes and failures.
- `global.set_process_name` renames the running process using the platform-specific helpers in `helpers_*.go`, and `ENV`/CLI flags also allow `liner -version` for version inspection.
- Logging is composed of the console/file logger plus a data logger and the in-memory `ringbuffer` used by `web.logtail`. `log_level: discard` disables the console logger, while `log_channel_size`, `log_backups`, `log_maxsize`, etc., tune rotation.
## Key Terms and Concepts

### Listeners
Responsible for accepting client connections on configured ports or in-memory endpoints:
- **HTTP/HTTPS**: HTTP/1.1/2/3 (QUIC) listeners with autocert or custom certificates, per-server protocol toggles and optional ChaCha20 PSK wrapping on HTTP listeners (HTTPS explicitly forbids PSK but supports JA4 shims, OCSP and cipher preferences).
- **SOCKS5**: SOCKS proxy (TCP), supports username/password, CSV/JSON/command auth tables, PSK transport encryption
- **SSH**: Full SSH server with shell, SFTP, remote command execution and port forwarding
- **DNS**: UDP, TCP, DoT and DoH/DoH3 frontends backed by `fastdns` dialers (udp/tcp/tls/http2/http3) with shared caching and per-request policy routing (`HOST`, `CNAME`, `TXT`, `PROXY_PASS`, `ERROR`).
- **Stream**: Generic TCP/PSK ingress for port forwarding or proxy protocol targets
- **Tunnel**: Intranet penetration listener plus remote tunnel clients (HTTP/1.1/2/3/WebSocket/SSH) using yamux/smux multiplexers, MASQUE-style endpoints under `/.well-known/masque/*` and allow-list enforcement for each announced `remote_listen`.
- **Redsocks**: Transparent TCP proxy (Linux only) for iptables-based interception that reads the original destination via `SO_ORIGINAL_DST`/`IP6T_SO_ORIGINAL_DST`.
- **MemoryListener**: In-process listener bound to reserved `240.0.0.0/8` addresses for zero-copy wiring between modules; HTTP tunnel servers, SSH listeners and remote tunnel clients push/pull `net.Conn` instances through these listeners.

### Handlers
Contain business logic, routing and protocol-specific behavior:
- **HTTPForwardHandler**: HTTP forward proxy (CONNECT & plaintext) whose policy template may return actions such as `bypass_auth`, `require_proxy_auth`, `reject`, `generate_204`, `reset` and custom dialer names; enforces deny lists, per-user `speed_limit` and `allow_client` attributes, applies TCP congestion hints (including the `brutal rate gain` syntax), merges `X-Forwarded-*`/`x-forwarded-ja4` headers and streams verbose per-user logs via `DataLogWriter`.
- **HTTPWebHandler**: Dispatches static indexes (autoindex template, Markdown rendering, CDNJS rewrites), WebDAV, DoH, reverse proxy (with HTTP/2 `:protocol` awareness, failure dumps, `set_headers` templates), TinyAuth-protected WebShell and Proxy endpoints, and logtail streaming; `/debug/pprof` and `/debug/vars` are exposed to loopback/private clients.
  - `handler_http_web_index.go`: Static file/directory serving with templated headers/body plus optional CDNJS assets and gzip.
  - `handler_http_web_dav.go`: WebDAV with AuthUser/TinyAuth gates.
  - `handler_http_web_doh.go`: DNS-over-HTTPS resolver backed by shared fastdns caches.
  - `handler_http_web_proxy.go`: Reverse proxy with header rewriting, pseudo-protocol support (WebSocket/HTTP/2 CONNECT) and per-request memory dialers.
  - `handler_http_web_shell.go`: PTY-backed shell sharing (websocket transport, template-driven UI, per-user quotas/home directories) with optional TinyAuth.
  - `handler_http_web_logtail.go`: Real-time log streaming sourced from the ring buffer (requires `allow_logtail` attribute).
- **HTTPTunnelHandler**: Implements MASQUE-like HTTP tunnels exposed under `/.well-known/masque/*`; authorizes users via `auth_table`, enforces `allow_tunnel` attributes, optional per-connection `speed_limit`/`tcp_congestion` settings, `allow_listens` IP sets and MemoryListener reuse.
- **SocksHandler**: SOCKS4/4a/5 handler with optional ChaCha20 PSK overlay, username/password auth wired to `auth_table`, policy templates, per-user `speed_limit`, IPv6 preference toggles and UDP associate support.
- **SniHandler**: TLS SNI splitter whose policy template selects upstream hostnames and whose dialer template can emit query strings or JSON blobs (`dialer`, `disable_ipv6`, `prefer_ipv6`) to steer connection families.
- **StreamHandler**: Plain TCP ingress that can terminate TLS, inject Proxy Protocol v1 headers, enforce `speed_limit`, propagate `X-Forwarded-For` to dialers and log GeoIP metadata.
- **SshHandler**: SSH server with inline/file/command-driven auth tables, banner templates, PTY shells (including spawning `liner` itself with `GOSH=1`), env injection, `authorized_keys`, SFTP subsystem, direct-tcpip forwarding and QUIC/yamux transport support.
- **DnsHandler**: DNS policy engine riding on `fastdns` dialers (udp/tcp/tls/doh/doh3) with LRU caches, request templates that may respond with `HOST`, `CNAME`, `TXT`, `ERROR` or `PROXY_PASS`, and structured data logging.
- **RedsocksHandler**: Linux-only transparent proxy that peeks TLS ClientHello data, evaluates dialer templates and forwards traffic through configured dialers after recovering the original destination.
- **TunnelHandler** (`handler_tunnel*.go`): Remote tunnel client implementing HTTP/1.1, HTTP/2, HTTP/3/WebSocket and SSH transports via yamux/smux, honoring `speed_limit`, `disable_keepalive` and `MemoryListener` hand-offs.

### Dialers
Establish upstream connections, optionally chaining through other dialers:
- **LocalDialer** (`dialer_local.go`): Direct socket dialer with interface binding, IPv4/IPv6 enable/prefer flags, configurable concurrency, TCP keepalive/pacing hooks and awareness of `DialerMemoryDialersContextKey`/`DialerMemoryListenersContextKey` so memory transports short-circuit instead of hitting the kernel.
- **HTTPDialer/HTTP2Dialer/HTTP3Dialer**: Forward requests via HTTP/1.1 (optional ChaCha20 PSK, MASQUE-style websocket CONNECT, ECH via HTTPS RRs), HTTP/2 (utls HelloChrome fingerprinting, per-proxy connection pools) or HTTP/3 (quic-go transport with optional websocket flag, `resolve=` override). All respect `DialerHTTPHeaderContextKey` so handlers can inject per-request headers.
- **SocksDialer**: SOCKS4/4a/5 dialer with PSK overlay and DNS resolver integration supporting both hostname and raw IP dialing, plus optional `socks5h` (remote resolution).
- **SSHDialer**: Maintains up to 64 reusable ssh.Client sessions (password and/or key auth, optional strict known_hosts checking) with idle timeouts, buffer tuning and fallback to memory dialers.
- **MemoryDialer**: Provides in-process `net.Conn` implementations tied to `MemoryListener` addresses (240/8), letting tunnels and SSH subsystems hop between modules without touching the OS stack.
- **Dialer Chain**: Multi-line `dialer.<name>` definitions are interpreted bottom-to-top (e.g., `local://` → `socks5://` → `ssh://` → `http3://`), and templates may return `dialer=` query strings or JSON to switch dialers dynamically.

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
├── main.go                         # Program entry, config loader, logging, TLS inspector wiring, cron runner and GOSH entrypoint
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
├── functions.go                    # Template functions (sprig additions, DNS/Geo helpers, fetch/readfile/savefile)
├── auth_user.go                    # Auth table loaders/checkers (file/command/hash, CSV/JSON/command with live reloads)
├── gosh.go                         # Embedded shell (mvdan/sh interpreter, readline UI, history/completion)
├── helpers.go                      # Networking helpers, PSK/ChaCha20 streams, MemoryListener/Dialer glue, file watchers
├── helpers_linux.go / helpers_others.go  # Platform-specific helpers (TCP info, pacing, process name, terminal sizing)
├── mime_types.go                   # MIME DB for static serving
├── x509.go                         # X.509 certificate utilities and self-signed RootCA helpers
├── liner-dll.go                    # Windows CGO shim to expose `liner()`/`linex()` symbols (buildmode=c-shared)
└── liner-py.go                     # Non-Windows CGO shim for building `liner.so` Python modules
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
// Sources may also be "-" (stdin) or https:// URIs, and matching .d overlays are merged.
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
- Misc: `set_process_name` (rename process), `cron` array (`spec`, `command`) rendered through the template funcs and executed via `/bin/bash -c`

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
Handlers may also emit `dialer=...` query strings or JSON blobs (see `SniHandler`) to switch dialers or flip IPv6 preferences dynamically, and schemes such as `http3+wss`, `socks5h`, `ssh2://` inherit the same parsing logic.

### HTTP/HTTPS Configuration
- Listener security: `psk` (ChaCha20 overlay for HTTP listeners only), `server_config` toggles (disable HTTP/2/3/TLS1.1, prefer ChaCha20, OCSP)
- Forward proxy: `policy`, `auth_table`, `dialer`, `tcp_congestion`, `deny_domains_table`, `speed_limit`, IPv6 toggles, `log`, `io_copy_buffer`, `idle_timeout`
- Tunnel sub-block: enable per-listen tunnels, `auth_table`, `allow_listens`, `disable_keepalive`
- Web sub-handlers: `dav`, `doh`, `index` (autoindex template/`cdnjs_zip` rewrite/markdown), `proxy` (TinyAuth or auth_table gated, header rewriting), `shell` (TinyAuth/AuthTable, template-based UI, PTY hook), and `logtail` (requires `allow_logtail=1`). Each location can be wrapped with TinyAuth, CDNJS middleware or `auth_table` gating.

### SOCKS / Stream / Tunnel / SNI / DNS / SSH
- **SOCKS**: `psk`, `auth_table`, `deny_domains_table`, IPv6 preferences, speed limits and policy/dialer templates (handlers add `X-Forwarded-*` context for upstream dialers).
- **Stream**: `proxy_protocol` (v1), TLS terminators, `dialer`, `dial_timeout`, `speed_limit` (TCP pacing) and structured logging.
- **Tunnel**: `remote_listen`, `proxy_pass` (TCP target or MemoryListener), optional dedicated `resolver`, `dial_timeout`, `dialer`, `disable_keepalive`, `log`.
- **SNI**: template-driven routing that can output hostnames, dialer names or JSON/query parameters to flip IPv6 behavior, with optional logging.
- **DNS**: `listen` addresses with schemes (`udp://`, `tcp://`, `tls://`, `https://`, `http3://`), optional TLS key pair, `policy` templates, `proxy_pass`, `cache_size`, `log`.
- DNS policies can return directives such as `HOST <ip...>`, `CNAME <name...>`, `TXT <value>`, `ERROR <rcode>` or `PROXY_PASS <dns-url>`, letting you short-circuit answers or select alternate upstream resolvers per query.
- **SSH**: `listen`, `server_version`, TCP buffers, keepalive toggle, `banner_file` (Go template), `host_key`, `auth_table`, `authorized_keys`, `shell`, `home`, `env`/`env_file`, `log`, TinyAuth-like gating provided via auth attributes.

### Authentication Configuration
- `auth_table` accepts inline `user:pass`, CSV/JSON files (hot reloaded by `FileLoader`), or external commands (detected automatically); also supports `file:///` URIs via shell quoting.
- Passwords may be stored plaintext, hex (`0x` prefixed) MD5/SHA1/SHA256, bcrypt (`$2y$`), or argon2id; `AuthUserCommandLoader` caches results when `cache_ttl` is set and `AuthUserCommandChecker` passes `USERNAME`/`PASSWORD` to helper commands.
- Command-based loaders/checkers can return JSON attributes; attributes such as `speed_limit`, `allow_tunnel`, `allow_client`, `allow_webdav`, `allow_logtail`, `allow_ssh`, `allow_webshell` drive handler decisions and can be combined with TinyAuth overlays.

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
go build -ldflags "-X main.version=1.0.$(git describe --tags)"
```

## Extension and Integration

### Embeddable Targets
- `liner-dll.go` exposes `liner()` (run main) and `linex()` (run the GOSH shell) for Windows consumers. Build with `CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC="zig cc -target x86_64-windows-gnu" go build -trimpath -buildmode=c-shared -o liner.dll` and import via `ctypes`.
- `liner-py.go` provides the same exports for POSIX/Python via `CGO_ENABLED=1 CGO_CFLAGS="$(python3-config --includes)" CGO_LDFLAGS="$(python3-config --ldflags)" go build -trimpath -buildmode=c-shared -o liner.so`, registering `PyInit_liner` for direct `import liner` usage.

### Embedded Shell (GOSH)
- `gosh.go` implements a readline-based shell (mvdan/sh parser, history search, custom key bindings). It sources `$GOSH_ENV` (default `$HOME/.profile`), honors interactive/non-interactive modes, exposes auto-completion, and is triggered either by running `liner` with `GOSH=1` or by configuring the SSH server with `shell: "$"`.

### Third-Party Library Dependencies
- `github.com/phuslu/log` – structured logging
- `github.com/phuslu/fastdns` – DNS protocol stack, DoH/DoH3 transports
- `github.com/phuslu/geosite`, `github.com/oschwald/maxminddb-golang/v2` – GeoIP/GeoSite DBs
- `github.com/puzpuzpuz/xsync/v4` – concurrent maps for dialers, auth tables, logtail clients
- `github.com/quic-go/quic-go`, `github.com/quic-go/quic-go/http3` – HTTP/3/QUIC transports
- `github.com/libp2p/go-yamux/v5`, `github.com/xtaci/smux` – tunnel/SSH multiplexers
- `github.com/refraction-networking/utls` – JA4/TLS fingerprint shaping
- `github.com/mileusna/useragent` – UA parsing for policy templates
- `github.com/coder/websocket` – WebSocket implementation used by WebShell/logtail/tunnel proxies
- `github.com/chzyer/readline`, `mvdan.cc/sh/v3`, `github.com/go-task/slim-sprig/v3` – GOSH shell UI/parser and templating helpers
- `github.com/creack/pty/v2` – PTY management for SSH/WebShell
- `github.com/robfig/cron/v3` – Cron scheduler for background commands
- `github.com/smallnest/ringbuffer` – in-memory log broadcaster

### Operational Scripts and Deployment

#### Bootstrap Script (`get.sh`)
- Detects the current architecture, downloads the latest release tarball, verifies SHA1 sums and updates the `liner` binary in-place when needed.
- Generates an opinionated `production.yaml` plus `users.csv` (with random PAC paths and credentials) so HTTPS forward proxy instances can start immediately.
- Installs the templated `liner@production.service` when systemd is detected, or writes keepalive scripts for OpenRC/local shells to keep the process running when systemd is unavailable.

#### System Service Units
- `liner@.service` runs `%i.yaml` configs, grants `cap_net_bind_service`/`cap_setuid`/`cap_setgid`, runs as user `phuslu`, and enforces `LimitNOFILE=1048576` with restart-on-failure semantics.
- `liner.openrc` expects symlinked instance names (e.g., `liner.production`), refuses direct invocations, and uses `supervise-daemon` to manage start/stop/status hooks around the matching binary and config file.

#### Vector Log Shipping
- `liner-vector.yaml` tails `data.*.log`, parses JSON log lines, annotates metadata (timestamp/app), filters records where `logger == "forward"`, and ships them to Elasticsearch via Vector.
- `liner-vector.service` ensures Vector is installed (downloading releases on the fly if needed), loads credentials from `liner-vector.env`, and runs `vector -c $(pwd)/liner-vector.yaml` within `/home/phuslu/liner`.
- `liner-vector.env` keeps `ELASTICSEARCH_URL`, `ELASTICSEARCH_USERNAME`, and `ELASTICSEARCH_PASSWORD` values for the Vector service so secrets stay out of the unit file.

#### Seashell Artifacts
- `seashell.bash.tpl` automates lightweight edge deployments by downloading releases, provisioning configs that expose HTTP/SSH listeners on `240.0.0.x` memory addresses, wiring tunnels via a cloud dialer, and emitting MOTD templates with GeoIP-derived fields.
- `seashell.dockerfile` builds the `phuslu/seashell` image on Alpine, installs troubleshooting tools plus runit, and creates an entrypoint that executes cloud-init style scripts before supervising user services.

## Common Issues and Notes

### Certificate Management
- HTTPS listeners support manual key/cert, autocert, multi-cert `server_config` entries
- TLS inspector can auto-select certs per SNI and emulate browser JA4 strings; ChaCha20 PSK overlays are only valid on HTTP listeners and the matching HTTP/SOCKS dialers (HTTPS listeners reject `psk`).

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
- Build and bootstrap helpers: `build.bash`, `get.sh`
- Service definitions: `liner@.service`, `liner.openrc`
- Vector shipping assets: `liner-vector.yaml`, `liner-vector.service`, `liner-vector.env`
- Seashell bootstrap artifacts: `seashell.bash.tpl`, `seashell.dockerfile`
- CLI helper: `gosh.go` (embedded shell used by cron/autop commands)
