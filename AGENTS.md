# AGENTS.md - Liner

This file applies to the entire repository. It is the working guide for agents
and contributors who modify, review, test, or operate Liner. When this document
and the code disagree, inspect the current implementation first and update this
file as part of the change.

## Project Summary

Liner is a high-performance Go network proxy and tunneling system. The project
is built around a configurable Listen -> Handle -> Dial pipeline:

```text
client request
  -> listener accepts a connection or packet
  -> handler authenticates, classifies, and routes it
  -> dialer opens the upstream path
  -> target service
```

Core capabilities include:

- HTTP and HTTPS forward proxying, including CONNECT, HTTP/2, HTTP/3, JA4
  inspection, browser-like TLS behavior, and optional PSK wrapping on plain HTTP
  listeners.
- MASQUE-style HTTP tunnels and reverse tunnels under `/.well-known/masque/*`
  and `/.well-known/reverse/*`.
- SOCKS4, SOCKS4a, SOCKS5, and SOCKS5H server and dialer support.
- SSH server and SSH dialer support, including shell, SFTP, direct-tcpip, and
  multiplexed transport.
- Standalone DNS listeners for UDP, TCP, and DoT, plus DoH through the HTTP web
  handler. Upstream resolvers support UDP, TCP, DoT, DoH, and DoH3.
- Redsocks transparent TCP proxying on Linux.
- Stream forwarding for generic TCP ingress, TLS termination, Unix sockets, and
  proxy protocol targets.
- TUN device forwarding through a gVisor network stack.
- GeoIP, GeoSite, user-agent, JA4, DNS, file, and HTTP-fetch aware policy
  templates.
- In-process `MemoryListener` and `MemoryDialer` paths for zero-copy handoff
  between modules using the reserved `240.0.0.0/8` address range.
- Structured console/file/data logging, in-memory log tailing, and optional
  Vector-based log shipping.

The module is `liner` and the repository currently targets `go 1.26`.

## Agent Operating Rules

- Read the relevant code before changing behavior. Prefer `rg` and `rg --files`
  for discovery.
- Keep edits scoped. Do not rewrite unrelated modules, logs, generated files, or
  local runtime artifacts.
- Preserve user work in a dirty tree. Never revert or overwrite changes you did
  not make unless explicitly asked.
- Use existing patterns: `Load(ctx)` for handler initialization,
  `DialContext(ctx, network, addr)` for dialers, template parsing through
  `Functions.ParseTemplate`, and structured logging through `github.com/phuslu/log`.
- Run `gofmt` on changed Go files. For documentation-only edits, no Go tests are
  required unless the documentation change exposed a code issue.
- Do not add new dependencies unless there is a clear reason. Prefer the
  standard library and existing dependencies already listed in `go.mod`.
- Avoid logging secrets. Auth headers, PSKs, private keys, passwords, cookies,
  and user command output require deliberate redaction or omission.
- Treat command execution paths as high risk: `cron.command`, auth command
  loaders/checkers, `fetch`, `readfile`, `savefile`, web shell, SSH shell, and
  deployment scripts must not expand trust boundaries casually.
- Do not rename misspelled internal identifiers as cleanup. Existing names such
  as `PerferIPv6` and context key strings containing `dailer` are part of the
  current code shape and may be referenced by logs or surrounding code.
- If adding a config key, update `Config` in `config.go`, parsing/merge logic in
  `NewConfig`, runtime wiring in `main.go`, examples, and this document.

## Tacit Codebase Conventions

These conventions are inferred from the existing codebase. They are not always
spelled out in comments, but following them keeps new work native to Liner.

### Minimal code style

- Prefer plain Go over framework-style structure. This repository is a compact
  `package main` program with feature files, not a layered enterprise layout.
- Keep code direct. A small local closure, a short helper, or a straightforward
  switch is preferred over a new abstraction when the behavior is used in one
  place.
- Avoid ceremony. Do not add service objects, registries, builders, option
  structs, or interfaces unless the existing code already needs polymorphism at
  that point.
- Names are descriptive at module boundaries and short in tight local scopes.
  Existing code commonly uses `h`, `d`, `req`, `ri`, `u`, `ln`, `conn`, `rconn`,
  `lconn`, `ctx`, and `err`.
- Keep files feature-oriented: `handler_<feature>.go`, `dialer_<protocol>.go`,
  resolver files, and helper files. Do not create package directories for a
  narrow feature.
- Let `gofmt` shape the code. Do not manually align fields or introduce
  decorative whitespace.
- Comments are sparse and functional. Add comments for unsafe tricks, protocol
  references, platform behavior, subtle performance constraints, or non-obvious
  security decisions. Do not narrate ordinary Go.
- Prefer simple control flow with early returns. Avoid deeply nested branches
  when validation, auth failure, parse failure, or dial failure can return
  immediately.
- Keep exported API surface small. Many types are exported only because the
  repository is one package and tests/tools may need them; avoid exporting new
  names without a practical reason.
- Match the repository's spelling and naming even when imperfect. Consistency is
  more valuable than opportunistic cleanup.

### Implementation taste

- Configuration drives behavior. New features should usually appear as config
  fields, templates, URL query parameters, or auth attributes before hard-coded
  policy is added.
- Runtime wiring belongs in `main.go` unless there is already a more local
  construction point.
- `Load(ctx)` is for validation, template parsing, auth loader setup, cache or
  certificate initialization, and other fail-fast work. Request handlers should
  not repeatedly parse stable config.
- Keep protocol parsing explicit with `netip`, `net`, `url`, `strconv`,
  `strings`, and protocol libraries. Avoid ad hoc string slicing except in
  measured hot paths or fixed wire formats.
- Prefer `cmp.Or`, `first`, `must`, small closures, and existing helper types
  where the codebase already uses them. Do not introduce a competing helper for
  the same idea.
- Use standard library types for contracts: `context.Context`, `net.Conn`,
  `net.Listener`, `http.Handler`, `http.RoundTripper`, `io.Reader`, and
  `io.Writer`.
- Interfaces stay tiny and behavior-shaped. `Dialer` is one method; HTTP
  handlers embed the standard `http.Handler` shape plus `Load(ctx)`.
- Keep feature state on the handler or dialer struct. Avoid package globals
  unless the existing design is intentionally sharing caches, transports, or
  process-wide state.
- Use existing cache primitives (`lru`, `xsync.Map`, `FileLoader`,
  `NewCachingMap`) instead of introducing another cache package.
- For multi-protocol behavior, prefer a scheme switch or small adapter over a
  generic framework. URL schemes are the extension mechanism for dialers and DNS
  resolvers.
- Avoid migrations that make config more abstract but less readable. The YAML is
  treated as an operator-facing API.

### Error and logging style

- Return errors from library-shaped methods and fail fast in top-level startup
  wiring. `main.go` commonly logs fatal after `Load` or listener setup errors.
- Preserve context in errors with `fmt.Errorf("...: %w", err)` when returning
  across a boundary.
- Log with stable structured keys. Reuse local names such as `trace_id`,
  `remote_ip`, `server_addr`, `forward_dialer_name`, `req_host`,
  `dns_server`, and `tun_name`.
- Include enough fields to debug routing decisions: selected policy, selected
  dialer, host/port, user name, network, and relevant config name.
- Do not log payloads or headers by default. If existing code logs headers in a
  path, be especially careful before adding more sensitive material.
- Treat close, EOF, and cancellation as normal where the protocol expects them.
  Avoid noisy error logs for ordinary connection teardown.
- When wrapping accepted connections, keep ownership obvious with `defer
  conn.Close()` near the top of the serving function and close both sides in
  copy goroutines where needed.

### Hot path expectations

- Allocation awareness matters. Existing code uses pools, reusable buffers,
  zero-copy conversions, and append-style helpers in DNS, HTTP, TUN, and copy
  paths.
- Do not replace append-based parsing, `bytebufferpool`, `sync.Pool`, or
  reusable request structs with cleaner but allocation-heavy code in hot paths.
- Keep DNS, GeoIP, regex, fetch, and file membership checks cached.
- Avoid reflection except where the code already uses it for config or generic
  dialer inspection. Reflection is not a general extension mechanism here.
- Keep goroutine lifetimes tied to contexts, listeners, connections, or explicit
  done channels.
- Use deadlines for external network operations when a config timeout exists or
  the surrounding code already sets one.
- Prefer streaming over buffering. Do not read whole request or tunnel bodies
  unless the protocol requires a complete message.
- Preserve memory listener and memory dialer shortcuts. They are part of the
  performance model, not just a test convenience.

### Compatibility posture

- Be conservative with behavior changes. Liner is configured by YAML, URL
  strings, templates, auth tables, and shell scripts; small parsing changes can
  break deployments.
- Existing config keys, policy return strings, auth attributes, log keys, and
  URL query parameters are compatibility surface.
- Additive changes are safer than semantic changes. If semantics must change,
  document the migration and keep the old path where practical.
- Platform-specific code should stay in the platform helper files or guarded by
  runtime checks. Linux-only features must fail clearly on unsupported systems.
- Keep build constraints and c-shared entry points intact when touching
  `liner-dll.go`, `liner-py.go`, or platform helpers.

## Runtime Startup Flow

`main.go` is the orchestration point:

1. If `GOSH=1`, start the embedded shell in `gosh.go` and exit normal server
   startup.
2. Select configuration:
   - `ENV=<name>` uses `<name>.yaml` when present.
   - CLI arguments ending in `.yaml` or `.json` override the selected file.
   - Windows with no args also checks for `<executable>.yaml`.
   - Default is stdin (`-`).
3. Load config with `NewConfig`:
   - YAML and JSON are supported.
   - Stdin auto-detects JSON when the content starts with `{`; otherwise YAML.
   - A file whose trimmed content starts with `https://` is treated as a remote
     config pointer and fetched by `ReadFile`.
   - `<config>.d/*<same-ext>` overlays are appended for supported top-level
     slices and dialer maps. Verify `NewConfig` before relying on overlay
     behavior for new fields.
   - Selected string fields beginning with `@` are replaced with file contents.
4. Configure logging:
   - Terminal/stderr mode writes console logs plus the in-memory ring buffer.
   - Daemon/file mode writes `<config>.log`, `data.<config>.log`, and
     `<config>.error.log`.
   - `log_level: discard` disables normal console/file output.
5. Optionally load `tcp-brutal` on Linux when brutal congestion is configured.
6. Build the global DNS resolver, GeoIP/GeoSite resolver, HTTP transport,
   template function set, local dialer, named dialer chains, and TLS inspector.
7. Register and serve SNI, HTTPS, HTTP, SOCKS, Redsocks, Stream, TUN, SSH,
   Tunnel, and DNS handlers as configured.
8. Register top-level `cron` jobs and execute rendered commands with
   `/bin/bash -c`.
9. Apply `global.set_process_name` when configured.
10. Wait for SIGTERM, SIGINT, SIGHUP, or interrupt, unload handlers, and close
    log writers.

## Architecture

### Listeners

Listeners accept traffic and hand it to a handler. Implementations are usually
created in `main.go` through `ListenConfig`, `http.Server`, TLS/QUIC setup, or
specialized loops.

- HTTP listens on TCP or a memory address. Plain HTTP may use ChaCha20 PSK via
  the listener wrapper.
- HTTPS listens on TCP with `TLSInspector` and can also start an HTTP/3 server on
  UDP unless disabled.
- SOCKS accepts TCP and optionally wraps the accepted connection with PSK.
- SSH accepts TCP or `MemoryListener` connections.
- DNS accepts UDP, TCP, or TLS-wrapped TCP depending on the listen URL scheme.
- Stream and Redsocks accept TCP.
- TUN creates and configures an OS TUN interface, then attaches a gVisor stack.
- Tunnel clients create remote listeners over HTTP/1.1, HTTP/2, HTTP/3, QUIC, or
  SSH transports.
- Memory listeners use `240.0.0.0/8` addresses to move `net.Conn` objects inside
  the process without a kernel TCP hop.

### Handlers

Handlers contain protocol logic, auth, policy execution, routing, logging, and
stream copying.

- `HTTPServerHandler` (`handler_http.go`) is the HTTP multiplexer. It builds
  `HTTPRequestInfo`, normalizes request metadata, decodes base64 well-known
  paths, extracts auth headers, resolves GeoIP/user-agent information, and
  dispatches to forward, tunnel, or web handlers.
- `HTTPForwardHandler` (`handler_http_forward.go`) implements HTTP forward proxy
  behavior. Policy control results include `bypass_auth`, `require_auth`,
  `require_proxy_auth`, `require_www_auth`, `generate_204`, `reject`/`deny`,
  `reset`/`close`, empty, or `proxy_pass`. Other non-control names such as
  `verify_auth` continue into the normal proxy-auth path. Dialer templates can
  return a dialer name, query string (`dialer=...&disable_ipv6=true`), or JSON
  object.
- `HTTPTunnelHandler` (`handler_http_tunnel.go`) handles MASQUE-like connect
  paths and reverse tunnel paths. It enforces `auth_table`, `allow_tunnel`,
  `allow_listens`, speed limits, and optional TCP congestion settings.
- `HTTPWebHandler` (`handler_http_web.go`) routes web subfeatures by location:
  static index, WebDAV, DoH, reverse proxy, web shell, and logtail. It also
  wires CDNJS, auth table, TinyAuth, and forward-auth middleware.
- `HTTPWebIndexHandler` serves static files, directories, Markdown, templates,
  CDNJS zip content, headers, and body templates.
- `HTTPWebDavHandler` serves WebDAV with auth table or TinyAuth gates.
- `HTTPWebDohHandler` serves DNS-over-HTTPS through `fastdns`.
- `HTTPWebProxyHandler` reverse-proxies HTTP, WebSocket, and pseudo-protocol
  traffic, supports header rewriting, memory dialers, and failure dumps.
- `HTTPWebShellHandler` serves PTY-backed shells over WebSocket.
- `HTTPWebLogtailHandler` streams the in-memory ring buffer and requires
  `allow_logtail`.
- `SocksHandler` implements SOCKS4/4a/5, username/password auth, PSK transport,
  UDP associate, policy templates, speed limits, and IPv6 preference flags.
- `SniHandler` inspects TLS ClientHello SNI without terminating TLS and forwards
  to a template-selected host and dialer.
- `StreamHandler` forwards raw TCP, optionally terminates TLS, injects proxy
  protocol v1, enforces speed limits, and logs GeoIP metadata.
- `SshHandler` serves SSH shell, command, SFTP, env, home, auth table,
  authorized keys, direct-tcpip forwarding, and optional `shell: "$"` re-entry
  into Liner's GOSH shell.
- `DnsHandler` applies DNS policy templates and can return `HOST`, `CNAME`,
  `TXT`, `ERROR`, or `PROXY_PASS` directives before proxying to upstream
  `fastdns` dialers.
- `RedsocksHandler` is Linux-only. It recovers the original destination with
  netfilter socket options, peeks TLS ClientHello when useful, and forwards with
  configured dialers.
- `TunHandler` creates a TUN device, configures routes/bypass routes, forwards
  TCP/UDP through a gVisor stack, handles DNS specially on port 53, and supports
  template-selected dialers.
- `TunnelHandler` is the remote tunnel client. It connects to an HTTP, HTTP/2,
  HTTP/3/QUIC, WebSocket, or SSH tunnel endpoint and forwards accepted remote
  connections to `proxy_pass` or a `MemoryListener`.

### Dialers

Dialers implement:

```go
type Dialer interface {
    DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}
```

Named dialers in config are built line by line in `main.go`. The current
implementation starts with the local dialer and applies each URL in order, so a
multi-line definition composes nested dialers around the previous layer.

Supported schemes:

- `local://<interface-or-bind-ip>` creates a direct `LocalDialer`.
- `http://`, `https://`, `ws://`, `wss://` create `HTTPDialer`.
- `http2://` creates `HTTP2Dialer`.
- `http3://` and `http3+wss://` create `HTTP3Dialer`.
- `socks4://`, `socks4a://`, `socks://`, `socks5://`, and `socks5h://` create
  `SocksDialer`.
- `ssh://` and `ssh2://` create `SSHDialer`.

Dialer behavior:

- `LocalDialer` handles direct socket dialing, DNS resolution, IPv4/IPv6
  selection, local address/device binding, TCP keepalive, buffer sizing, local
  address forbidding, and memory dialer short-circuiting.
- HTTP dialers support auth, PSK, WebSocket, ECH, CA/client certificates,
  `resolve=`, custom user-agent, and per-request headers from context.
- HTTP/2 and HTTP/3 dialers reuse transports and tune stream/window behavior.
- SOCKS dialers support SOCKS4/4a/5, SOCKS5H remote resolution, auth, PSK, and
  DNS integration.
- SSH dialers maintain reusable SSH clients, support password/private key auth,
  optional strict known-host checks, idle timeouts, and buffer tuning.
- `MemoryDialer` opens streams against a mux session for a specific
  `240.x.x.x:port` address.

### Context Keys

Important dialer context values live in `dialer.go`:

- `DialerHTTPHeaderContextKey` injects extra HTTP headers into upstream dialers.
- `DialerDisableIPv6ContextKey` forces IPv4 behavior.
- `DialerPreferIPv6ContextKey` prefers IPv6 where supported.
- `DialerMemoryDialersContextKey` carries available memory dialers.
- `DialerMemoryListenersContextKey` carries available memory listeners.

## Configuration Notes

Top-level config sections are:

- `global`
- `cron`
- `dialer`
- `sni`
- `https`
- `http`
- `socks`
- `redsocks`
- `tunnel`
- `stream`
- `tun`
- `ssh`
- `dns`

Important global options:

- Logging: `log_dir`, `log_level`, `log_backups`, `log_maxsize`,
  `log_localtime`, `log_channel_size`.
- Network dialing: `forbid_local_addr`, `dial_timeout`, `dial_read_buffer`,
  `dial_write_buffer`, `tcp_read_buffer`, `tcp_write_buffer`,
  `idle_conn_timeout`, `max_idle_conns`.
- DNS: `dns_server`, `dns_cache_duration`, `dns_cache_size`.
- TLS: `tls_insecure`, `tls_cache_size`, `autocert_dir`, `disable_http3`.
- Geo: `geoip_dir`, `geoip_cache_size`, `geosite_cache_size`, `disable_geoip`,
  `disable_geosite`.
- Runtime: `disable_brutal`, `disable_ipv6`, `set_process_name`.

Current include behavior:

- Config files can be YAML or JSON.
- Matching `.d` overlay directories are appended by `NewConfig`.
- `@file` expansion is implemented for selected policy/dialer/header/body/pass
  fields. Do not assume every string field supports it.
- HTTPS handlers reject `psk`; PSK wrapping is valid on plain HTTP listeners and
  compatible client dialers.
- `cron` is top-level, not under `global`.

### Policy Templates

`functions.go` combines slim-sprig with Liner-specific helpers. Common helpers
include:

- DNS and network: `dnsResolve`, `nslookup`, `host`, `domain`, `hasIPv6`,
  `isInNet`, `ipRange`, `ipInt`.
- Geo: `geoip`, `country`, `geosite`.
- Matching: `contains`, `hasPrefix`, `hasSuffix`, `hasPrefixes`,
  `hasSuffixes`, `wildcardMatch`, `regexMatch`, `inFileLine`, `inFileIPSet`.
- IO and fetch: `fetch`, `readfile`, `savefile`, `xml2map`.
- TLS: `greased`.

Template data varies by handler:

- HTTP forward/tunnel templates receive `Request`, `RealIP`, `ClientHelloInfo`,
  `JA4`, `User`, `UserAgent`, and `ServerAddr`.
- SOCKS templates receive `Request` and `ServerAddr`.
- SNI templates receive `Request`.
- DNS templates receive `Request`.
- TUN dialer templates receive `Request`, `ServerAddr`, and `TLSClientHello`.

For HTTP, SOCKS, SNI, and TUN dialer templates, returning a plain dialer name,
query string, or JSON object can switch dialers and IPv6 behavior:

```text
proxy1
dialer=proxy1&disable_ipv6=true
{"dialer":"proxy1","prefer_ipv6":true}
```

## Configuration Examples

### HTTP forward proxy with reverse tunnel server

```yaml
http:
  - listen: [":8080"]
    forward:
      policy: |
        {{ if inFileLine "blocked.txt" (domain .Request.Host) }}
          reject
        {{ else if .Request.Header.Get "proxy-authorization" }}
          verify_auth
        {{ else }}
          require_proxy_auth
        {{ end }}
      dialer: local
      auth_table: users.csv
      speed_limit: 10000000
      log: true
    tunnel:
      enabled: true
      auth_table: users.csv
      allow_listens: ["127.0.0.1", "240.0.0.0/8"]
      log: true
```

### Remote tunnel client

```yaml
dialer:
  cloud: "http3://user:pass@example.com:443/"

tunnel:
  - remote_listen: ["127.0.0.1:10022"]
    proxy_pass: "192.168.50.1:22"
    resolver: "https://8.8.8.8/dns-query"
    dialer: cloud
    dial_timeout: 5
```

### SOCKS proxy

```yaml
socks:
  - listen: ["0.0.0.0:1080"]
    psk: "shared-secret"
    forward:
      auth_table: users.csv
      policy: |
        {{ if hasSuffix ".local" .Request.Host }}reject{{ end }}
      dialer: local
      log: true
```

### TUN forwarding

```yaml
tun:
  - name: tun-liner-1
    address: 198.18.0.1/15
    routes:
      - 0.0.0.0/0
      - -192.168.0.0/16
    mtu: 1420
    dns_server: https://1.1.1.1/dns-query
    forward:
      dialer: proxy1
      dial_timeout: 10
      udp_timeout: 120
      log: true
```

### DNS listener

```yaml
dns:
  - listen:
      - udp://127.0.0.1:5353
      - tcp://127.0.0.1:5353
    proxy_pass: https://8.8.8.8/dns-query
    policy: |
      {{ if eq .Request.Domain "test.local" }}HOST 127.0.0.1{{ else }}PROXY_PASS https://1.1.1.1/dns-query{{ end }}
    cache_size: 4096
    log: true
```

### SNI routing

```yaml
sni:
  enabled: true
  forward:
    policy: |
      {{ if wildcardMatch "*.example.com|example.com" .Request.ServerName }}
        {{ .Request.ServerName }}:443
      {{ end }}
    dialer: "dialer=proxy1&prefer_ipv6=false"
    log: true
```

## Source Map

Primary entry points:

- `main.go`: startup, config selection, logging, resolver/dialer construction,
  listener registration, cron jobs, shutdown.
- `config.go`: config schema, YAML/JSON loading, `.d` overlays, `@file`
  expansion, validation.
- `dialer.go`: dialer interface, context keys, memory dialer primitives.
- `helpers.go`: shared networking, connection wrappers, file loaders, PSK and
  ChaCha20 helpers, copy utilities, caching primitives.
- `helpers_linux.go`, `helpers_darwin.go`, `helpers_windows.go`,
  `helpers_zzz.go`: platform-specific listen/socket/TUN/process helpers.

Dialers:

- `dialer_local.go`: direct socket dialer, DNS racing, IPv4/IPv6 behavior,
  interface binding, memory dialer handling.
- `dialer_http.go`: HTTP/1.1 and WebSocket proxy dialer.
- `dialer_http2.go`: HTTP/2 proxy dialer.
- `dialer_http3.go`: HTTP/3/QUIC proxy dialer.
- `dialer_socks.go`: SOCKS dialer.
- `dialer_ssh.go`: SSH dialer and muxed sessions.

HTTP handlers:

- `handler_http.go`: HTTP request normalization and dispatch.
- `handler_http_forward.go`: HTTP forward proxy.
- `handler_http_tunnel.go`: HTTP tunnel and reverse tunnel server.
- `handler_http_web.go`: web location router and middleware.
- `handler_http_web_index.go`: static files, autoindex, Markdown, CDNJS.
- `handler_http_web_dav.go`: WebDAV.
- `handler_http_web_doh.go`: DoH.
- `handler_http_web_proxy.go`: reverse proxy.
- `handler_http_web_shell.go`: web shell.
- `handler_http_web_logtail.go`: logtail streaming.

Other handlers:

- `handler_socks.go`: SOCKS server.
- `handler_sni.go`: TLS SNI router.
- `handler_stream.go`: TCP stream forwarding.
- `handler_ssh.go`: SSH server.
- `handler_dns.go`: DNS server.
- `handler_redsocks.go`: Linux transparent proxy.
- `handler_tun.go`: TUN device and gVisor stack forwarding.
- `handler_tunnel.go`, `handler_tunnel_http.go`, `handler_tunnel_http2.go`,
  `handler_tunnel_http3.go`, `handler_tunnel_ssh.go`: remote tunnel client
  transports.

Resolvers, auth, TLS, and utilities:

- `resolver_dns.go`: shared `fastdns` resolver pool and caches.
- `resolver_geo.go`: GeoIP/GeoSite resolver and template-facing metadata.
- `functions.go`: template helper library.
- `auth_user.go`: auth table loading/checking, CSV/JSON/command support,
  password hash verification, user attributes.
- `tls.go`: TLS inspector, JA4 extraction, autocert, SNI certificate selection.
- `x509.go`: X.509 and local Root CA helpers.
- `mime_types.go`: static serving MIME database.
- `gosh.go`: embedded shell using `mvdan.cc/sh/v3` and readline.
- `liner-dll.go`: Windows c-shared exports.
- `liner-py.go`: POSIX/Python c-shared exports.

Operational assets:

- `example.yaml`, `test.yaml`, `phuslu.yaml`, `tt.yaml`: config examples or
  local configs.
- `build.bash`: release and Python wheel build helpers.
- `get.sh`: bootstrap/install/update script.
- `liner@.service`, `liner.openrc`: system service templates.
- `liner-vector.yaml`, `liner-vector.service`, `liner-vector.env`: Vector log
  shipping.
- `seashell.bash.tpl`, `seashell.dockerfile`: edge deployment artifacts.

Runtime artifacts such as `liner`, `*.log`, `data.*.log`, `autocert/`, `lego/`,
and `.codex/` may exist locally. Ignore them unless the task explicitly targets
runtime state.

## Development Workflows

### Add or modify a dialer

1. Study the closest existing dialer.
2. Implement `DialContext(ctx, network, addr)` in `dialer_<name>.go`.
3. Thread the underlay dialer through the new type if it chains.
4. Register the URL scheme in the `dialerof` switch in `main.go`.
5. Parse options from `url.Query()` consistently with existing dialers.
6. Respect context cancellation, deadlines, memory dialers, TLS cache, DNS
   resolver, IPv6 flags, and structured logging as applicable.
7. Add config examples and focused tests when practical.

### Add or modify a handler

1. Study a handler with the same lifecycle shape.
2. Add or update config fields in `config.go`.
3. Implement `Load(ctx)` for validation, auth table loading, and template
   parsing.
4. Implement serving logic with cancellation, deadlines, clear error handling,
   and structured log fields.
5. Wire construction and listener setup in `main.go`.
6. Update examples, this file, and tests.

### Add a web subhandler

1. Add a focused file named `handler_http_web_<feature>.go`.
2. Add config under `HTTPConfig.Web`.
3. Register it in `HTTPWebHandler.Load`.
4. Decide middleware support explicitly: CDNJS, auth table, TinyAuth,
   forward-auth, or none.
5. Ensure location matching, prefix stripping, and auth attributes are documented.

### Add a template helper

1. Implement the method in `functions.go`.
2. Register it in `Functions.Load`.
3. Cache expensive operations with existing cache types when safe.
4. Keep network and file operations context-aware where possible.
5. Document input, output, and failure behavior in this file or examples.

### Add an auth attribute

1. Add enforcement in the relevant handler.
2. Document the attribute name and accepted values.
3. Update `auth_user.csv`, `users.csv`, or examples if the attribute is
   user-facing.
4. Preserve existing behavior for users without the attribute unless the task
   explicitly changes defaults.

## Authentication and Authorization

`auth_table` values are interpreted by `NewAuthUserLoaderFromTable`:

- `*.csv` without spaces is loaded as CSV and hot-reloaded through `FileLoader`.
- `*.json` without spaces is loaded as line-delimited JSON and hot-reloaded.
- Other values are treated as commands returning CSV or JSON.

Password formats:

- Plaintext exact match.
- `0x`-prefixed MD5, SHA1, or SHA256 digest.
- bcrypt hashes with `$2y$`.
- argon2id hashes in the documented `$argon2id$...` format.

Common user attributes:

- `speed_limit`: positive value overrides handler speed limit; negative value
  means privileged/no limit in HTTP tunnel and forward handlers.
- `no_log=1`: disables per-user forward logging where supported.
- `allow_client`: HTTP forward client gating.
- `allow_tunnel`: HTTP tunnel permission; `0` denies, `-1` can bypass some
  allow-list checks.
- `allow_webdav`, `allow_index`, `allow_proxy`, `allow_webshell`,
  `allow_logtail`: web feature gates.
- `allow_ssh`: SSH server permission.

## Performance Guidance

- Avoid per-request allocations on hot paths. Reuse existing pools such as
  `sync.Pool`, `bytebufferpool`, DNS request pools, and TUN copy buffer pools.
- Respect context cancellation and deadlines to avoid goroutine leaks.
- Use `io.Copy` or existing copy helpers for streaming paths unless a protocol
  requires framing.
- Preserve connection reuse for HTTP/2, HTTP/3, SSH, DNS, and tunnel muxes.
- Be careful with log volume in packet or stream loops. Use data logs only where
  the handler already supports them.
- Keep DNS, GeoIP, regex, fetch, and file checks cached when repeated per
  request.
- Do not introduce global locks on forwarding hot paths without measuring or
  isolating the impact.
- Memory listeners/dialers are used to avoid kernel round trips; preserve this
  behavior when changing tunnel, SSH, HTTP, or local dialer code.
- Linux TCP pacing and congestion hooks may be unsupported on other platforms.
  Keep unsupported paths explicit and non-fatal unless the feature requires them.

## Security Guidance

- Validate listener addresses, tunnel `remote_listen`, TUN routes, proxy targets,
  and user-provided host/port strings with structured parsers (`netip`, `url`,
  `net.SplitHostPort`) instead of ad hoc string slicing.
- Preserve `forbid_local_addr` semantics in new outbound paths.
- Do not allow HTTPS listener PSK; `NewConfig` intentionally rejects it.
- Keep `allow_listens` enforcement for reverse tunnels. Memory addresses are not
  automatically safe just because they are in-process.
- Be cautious with `X-Forwarded-For`: HTTP only trusts it for authenticated users
  or loopback clients.
- Avoid adding request dumps that include credentials, cookies, auth headers, or
  tunnel payloads.
- For shell, SSH, auth command, and cron changes, document the trust model and
  never silently broaden environment inheritance.

## Testing and Validation

Common commands:

```bash
go test ./...
go test ./... -count=1
go test -v -run TestResolverLookup
go build -v
go build -trimpath -ldflags "-X main.version=1.0.$(git rev-list --count HEAD)"
gofmt -w <changed-go-files>
```

Use targeted tests for narrow changes and broader tests for shared behavior.
Examples:

- Config loader changes: add or run tests that cover YAML, JSON, stdin-like
  content, `.d` overlays, and `@file` expansion.
- Dialer changes: cover URL parsing, context cancellation, IPv4/IPv6 flags, and
  underlay chaining.
- Handler changes: cover auth decisions, policy outputs, failure responses, and
  log-sensitive branches.
- DNS changes: cover all policy directives and resolver schemes.
- TUN, Redsocks, tcp-brutal, privileged ports, and OS network configuration may
  need elevated privileges or platform-specific manual validation.

If sandbox cache permissions become noisy, using a cache under `/tmp` is
acceptable, for example:

```bash
GOCACHE=/tmp/liner-go-build go test ./...
```

## Operational Notes

- `get.sh` downloads release artifacts, verifies checksums, updates the binary,
  creates production configs/users, and installs service scripts when possible.
- `build.bash` installs a custom Go toolchain, applies HTTP/2 buffer patches in
  the toolchain/module cache, builds release archives, and can build the Python
  shared module.
- `liner@.service` runs instance configs such as `production.yaml`, sets
  capabilities, runs as user `phuslu`, and raises `LimitNOFILE`.
- `liner.openrc` supports OpenRC/supervise-daemon style service management.
- Vector assets tail `data.*.log`, parse JSON records, filter forward logs, and
  ship to Elasticsearch.
- Seashell assets build and bootstrap lightweight edge environments with memory
  listeners and cloud tunnels.

## Common Pitfalls

- `cron` is top-level in config. Do not document or implement it as
  `global.cron` without a deliberate migration.
- Standalone `dns.listen` supports `udp://`, `tcp://`, and `tls://`; DoH is
  exposed through HTTP web `doh`, while DoH/DoH3 upstreams are resolver schemes.
- Top-level `tunnel` is the remote client. Server-side reverse tunnel handling is
  configured under `http[].tunnel` or `https[].tunnel`.
- `remote_listen` currently expects exactly one address in `TunnelHandler.Load`.
- TUN default address is `198.18.0.1/15`, default MTU is `1420`, default stack
  queue size is `1024`, and negative route entries mean bypass prefixes.
  Windows adds a high-metric `0.0.0.0/0` fallback when `routes` is empty so
  source-bound clients such as `curl --interface 198.18.0.1` can select the TUN
  without replacing normal default routing.
- The reserved memory address range is `240.0.0.0/8`; ensure uniqueness of
  memory listener addresses across HTTP, SSH, and tunnels.
- Config overlay merge behavior is manual in `NewConfig`; new top-level fields
  must be explicitly merged.
- `README.md` is intentionally minimal. Use this file and current source code as
  the project map.
