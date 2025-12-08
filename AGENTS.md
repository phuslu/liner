# Liner - Agent Instructions

## Project Overview
Liner is a high-performance, modular network proxy and tunneling tool developed in Go.
- **Language**: Go 1.25+
- **Architecture**: Modular design based on a three-tier "Listen-Handle-Dial" architecture
- **Core Features**: HTTP/HTTPS/SOCKS5 proxy, intranet penetration, DNS service, SNI routing, GeoIP/GeoSite intelligent traffic splitting

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
1. **Modularity**: Each functional module is independently implemented and combined through configuration
2. **Extensibility**: Flexible combination of multiple protocols and transport methods
3. **Performance First**: Connection pooling, caching, concurrency optimization
4. **Intelligent Routing**: Traffic splitting based on GeoIP/GeoSite/Policy

## Key Terms and Concepts

### Listeners
Responsible for accepting client connections on specified ports:
- **HTTP/HTTPS**: Support HTTP/1.1, HTTP/2, HTTP/3 (QUIC)
- **SOCKS5**: SOCKS proxy protocol
- **SSH**: SSH server
- **DNS**: DNS service (UDP/TCP/DoT)
- **Stream**: Generic port forwarding
- **Tunnel**: Intranet penetration listener

### Handlers
Contains specific business logic and protocol processing:
- **HTTPForwardHandler**: HTTP forward proxy, handles CONNECT method and HTTP forwarding
- **HTTPWebHandler**: Static file service, WebDAV, DoH, WebShell
- **HTTPTunnelHandler**: HTTP tunnel protocol handling
- **SocksHandler**: SOCKS5 protocol handshake and forwarding
- **SniHandler**: TLS traffic splitting based on SNI
- **StreamHandler**: Simple TCP port forwarding
- **SshHandler**: SSH server implementation
- **DnsHandler**: DNS query processing

### Dialers
Establish connections to upstream servers:
- **LocalDialer**: Direct local network connection, supports interface binding, IPv4/IPv6 preference
- **HTTPDialer**: Connect through HTTP/HTTPS proxy
- **HTTP2Dialer**: Connect through HTTP/2 proxy
- **HTTP3Dialer**: Connect through HTTP/3 (QUIC) proxy
- **SocksDialer**: Connect through SOCKS4/SOCKS5 proxy
- **SSHDialer**: Connect through SSH tunnel
- **Dialer Chain**: Support multi-layer proxy nesting (e.g., SOCKS over SSH)

### Core Utility Components

#### GeoResolver (Geolocation Resolver)
- Integrates MaxMind GeoIP database (country, city, ISP, ASN)
- Integrates GeoSite domain classification database
- Provides DNS resolution functionality
- Cache mechanism optimizes query performance
- Location: `resolver_geo.go`

#### TLSInspector (TLS Inspector)
- TLS handshake information inspection and fingerprinting (JA4)
- Dynamic certificate management (supports autocert for automatic Let's Encrypt certificates)
- Intelligent TLS configuration generation to simulate browser fingerprints
- Location: `tls.go`

#### Functions (Template Function Library)
- Provides dynamic logic functions for use in configuration files
- Supports routing policies based on GeoIP
- Supports regular expressions, file reading, HTTP requests, etc.
- Location: `functions.go`

## Directory Structure

```
liner/
├── main.go                         # Program entry, initialization and startup of all services
├── config.go                       # Configuration definition and loading (YAML/JSON)
├── dialer.go                       # Dialer interface and LocalDialer implementation
├── dialer_http.go                  # HTTP/HTTPS Dialer
├── dialer_http2.go                 # HTTP/2 Dialer
├── dialer_http3.go                 # HTTP/3 (QUIC) Dialer
├── dialer_socks.go                 # SOCKS4/SOCKS5 Dialer
├── dialer_ssh.go                   # SSH Dialer
├── handler_http.go                 # HTTP main handler
├── handler_http_forward.go         # HTTP forward proxy handling
├── handler_http_tunnel.go          # HTTP tunnel handling
├── handler_http_web.go             # HTTP Web service foundation
├── handler_http_web_dav.go         # WebDAV implementation
├── handler_http_web_doh.go         # DNS over HTTPS
├── handler_http_web_index.go       # Static file service
├── handler_http_web_proxy.go       # Reverse proxy
├── handler_http_web_shell.go       # Web terminal
├── handler_http_web_fastcgi.go     # FastCGI support
├── handler_socks.go                # SOCKS5 handler
├── handler_sni.go                  # SNI routing handler
├── handler_stream.go               # Port forwarding handler
├── handler_ssh.go                  # SSH server handler
├── handler_dns.go                  # DNS server handler
├── handler_redsocks.go             # Redsocks transparent proxy handler
├── handler_tunnel_*.go             # Various tunnel protocol implementations
├── resolver.go                     # DNS resolver foundation
├── resolver_geo.go                 # GeoIP/GeoSite resolver
├── resolver_getter.go              # DNS resolver getter function
├── tls.go                          # TLS handling and fingerprinting
├── functions.go                    # Template function library
├── auth_user.go                    # User authentication
└── x509.go                         # X.509 certificate handling
```

## Code Patterns and Conventions

### Configuration Loading Pattern
```go
// All handlers implement the Load() method for initialization
type HTTPHandler interface {
    Load() error
    ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// Configuration files support YAML and JSON, support .d directory pattern
config, err := NewConfig("config.yaml")
```

### Dialer Interface Specification
```go
type Dialer interface {
    DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Dialer chain composition
underlay := &LocalDialer{...}
proxy := &SocksDialer{Dialer: underlay, ...}
```

### Handler Loading Pattern
```go
handler := &HTTPServerHandler{
    ForwardHandler: &HTTPForwardHandler{...},
    TunnelHandler:  &HTTPTunnelHandler{...},
    WebHandler:     &HTTPWebHandler{...},
}

// All sub-handlers must call Load()
for _, h := range []HTTPHandler{
    handler.ForwardHandler,
    handler.TunnelHandler,
    handler.WebHandler,
    handler,
} {
    if err := h.Load(); err != nil {
        log.Fatal(err)
    }
}
```

### Context Passing Key Information
```go
// Context Keys for passing dialer configuration
var (
    DialerHTTPHeaderContextKey      any = &DialerContextKey{"dailer-http-header"}
    DialerDisableIPv6ContextKey     any = &DialerContextKey{"dailer-disable-ipv6"}
    DialerMemoryDialersContextKey   any = &DialerContextKey{"dailer-memory-dialers"}
)

// Usage example
ctx = context.WithValue(ctx, DialerDisableIPv6ContextKey, true)
conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
```

### Error Handling
```go
// Unified error handling pattern
if err != nil {
    log.Error().Err(err).Str("address", addr).Msg("description")
    return fmt.Errorf("operation failed: %w", err)
}
```

## Common Operation Scenarios

### Adding a New Dialer
1. Create `dialer_<protocol>.go` in the root directory
2. Implement the `Dialer` interface
3. Add URL scheme parsing in the `dialerof` function in `main.go`
4. Update configuration documentation

### Adding a New Handler
1. Create `handler_<feature>.go` in the root directory
2. Implement the `Load()` method and core logic
3. Register and start in `main.go`
4. Add configuration struct in `config.go`

### Adding Routing Policy
1. Add template functions in `functions.go`
2. Use Go template syntax in the `policy` field of the configuration file
3. Access GeoIP, GeoSite, request headers, etc.

### Configuration Examples

#### HTTP Proxy Configuration
```yaml
http:
  - listen:
      - "0.0.0.0:8080"
    forward:
      policy: "direct"  # Or use template: {{ if geoip_cn .RemoteAddr }}direct{{ else }}proxy{{ end }}
      dialer: "local"
```

#### SOCKS5 Proxy Configuration
```yaml
socks:
  - listen:
      - "0.0.0.0:1080"
    auth_table: "authuser.csv"
    forward:
      dialer: "local"
```

#### Intranet Penetration Configuration
```yaml
tunnel:
  - role: server
    listen:
      - "0.0.0.0:4433"
    server_name: "tunnel.example.com"
    keyfile: "/path/to/key.pem"
```

#### SNI Routing Configuration
```yaml
sni:
  enabled: true
  forward:
    policy: |
      {{ if geoip_cn .RemoteAddr }}direct{{ else }}proxy{{ end }}
    dialer: "local"
```

## Performance Optimization Features

### Connection Management
- TCP Keep-Alive default 30 seconds
- Connection pool reuse (HTTP/2, SSH)
- MemoryListener for local inter-module communication

### Caching Mechanisms
- DNS query result caching
- GeoIP/GeoSite query result caching (LRU)
- TLS session caching
- Template function result caching

### Concurrency Control
- Goroutine pool management (especially SSH, HTTP/2)
- Concurrent DNS resolution (IPv4/IPv6)
- Request rate limiting and traffic control

### Zero-Copy Optimization
- Use `io.Copy` for efficient data forwarding
- Configurable buffer sizes
- TCP congestion control algorithm selection

## Important Configuration Items

### Global Configuration
- `dns_server`: DNS server (supports DoH/DoT)
- `geoip_dir`: GeoIP database directory
- `log_level`: Log level (debug/info/warn/error/discard)
- `dial_timeout`: Dial timeout duration
- `max_idle_conns`: Maximum idle connections
- `tcp_read_buffer`/`tcp_write_buffer`: TCP buffer sizes

### Dialer Configuration
Supports multi-line configuration, each line represents a proxy layer, building the proxy chain from bottom to top:
```yaml
dialer:
  proxy_chain: |
    local://eth0
    socks5://user:pass@proxy1.com:1080
    ssh://user@proxy2.com:22?key=/path/to/key
```

### Authentication Configuration
- `auth_table`: Supports `user:pass` or `file:///path/to/auth.csv` format
- CSV format: `username,password,permissions`

## Debugging and Testing

### Logging System
- Main log: Records program runtime status
- Data log: Records proxy traffic details (requires `forward.log` to be enabled)
- Error log: Captures panic and error output
- Supports log rotation and compression

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
Project includes MCP server for configuration file generation:
- `generate_liner_config`: Generate complete configuration
- `generate_http_config`: Generate HTTP configuration
- `generate_dialer_config`: Generate Dialer configuration
- `validate_liner_config`: Validate configuration correctness
- See `.mcp.json` for details

### Third-Party Library Dependencies
- `github.com/phuslu/log`: High-performance logging library
- `github.com/oschwald/maxminddb-golang`: GeoIP database
- `github.com/phuslu/geosite`: GeoSite domain classification
- `github.com/quic-go/quic-go`: HTTP/3 (QUIC) support
- `golang.org/x/net/http2`: HTTP/2 support

## Common Issues and Notes

### Certificate Management
- Supports manual certificate configuration (keyfile/certfile)
- Supports autocert for automatic Let's Encrypt certificate application
- Supports multi-certificate management based on SNI

### Memory Listener
- Used for inter-module communication, avoiding network stack overhead
- Reserved IP range: `240.0.0.0/8`
- Applicable to Tunnel and SSH modules

### IPv6 Support
- Supports IPv4/IPv6 dual stack
- Configurable preference (prefer_ipv6) or disable (disable_ipv6)
- Concurrent resolution of both address families to improve performance

### Transparent Proxy
- Redsocks mode supports iptables transparent proxy (Linux only)
- SNI mode supports TLS traffic splitting (without decryption)

## Development Guide

### Steps to Add New Features
1. Reference existing implementations (e.g., `handler_http.go`)
2. Follow naming conventions: `handler_<feature>.go`, `dialer_<protocol>.go`
3. Implement necessary interfaces (`Load()`, `ServeHTTP()`, etc.)
4. Register new module in `main.go`
5. Update configuration structs and documentation
6. Write test cases

### Code Style
- Follow Go standard library style
- Use `gofmt` to format code
- Error handling must be explicit, cannot ignore
- Exported types and functions must have comments
- Prefer standard library, reduce third-party dependencies

### Performance Considerations
- Avoid unnecessary memory allocations
- Use object pool reuse (e.g., `sync.Pool`)
- Watch out for goroutine leaks
- Use context appropriately to control timeouts
- Use streaming for large data transfers

## Related Files
- Configuration examples: `*.yaml` files in project root
- Build script: `build.bash`, `make.bash`
