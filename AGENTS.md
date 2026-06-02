# AGENTS.md - Liner

This file applies to the whole repository. It is a working contract for agents
and contributors changing Liner. If this file and the current code disagree,
trust the code first, then update this file in the same change.

## Project Shape

Liner is a compact `package main` Go network proxy built around a repeated
pipeline:

```text
listener accepts a connection or packet
  -> handler authenticates, classifies, routes, logs, and copies
  -> dialer opens the upstream path
```

Most complexity is external protocol complexity: HTTP/1.1, HTTP/2, HTTP/3,
QUIC, MASQUE-like tunnels, SOCKS, SSH, DNS, WireGuard, TUN, platform socket
APIs, auth tables, templates, and operator YAML. Do not add an internal
framework layer on top of that unless nearby code already proves the abstraction
is shared and useful.

The module is `liner` and currently targets `go 1.26`.

## Agent Operating Rules

- Read the relevant code before changing behavior. Prefer `rg` and `rg --files`
  for discovery.
- Keep edits scoped. Do not rewrite unrelated modules, logs, generated files, or
  local runtime artifacts.
- Preserve user work in a dirty tree. Never revert or overwrite changes you did
  not make unless explicitly asked.
- Use existing patterns: `Load(ctx)` for handler initialization,
  `DialContext(ctx, network, addr)` for dialers, template parsing through
  `Functions.ParseTemplate`, and structured logging through
  `github.com/phuslu/log`.
- Run `gofmt` on changed Go files. For documentation-only edits, no Go tests are
  required unless the documentation change exposed a code issue.
- Do not add new dependencies unless there is a clear reason. Prefer the
  standard library and existing dependencies already listed in `go.mod`.
- Avoid logging secrets. Auth headers, PSKs, private keys, passwords, cookies,
  and user command output require deliberate redaction or omission.
- Treat command execution paths as high risk: `cron.command`, auth command
  loaders/checkers, `fetch`, `readfile`, `savefile`, web shell, SSH shell, and
  deployment scripts must not expand trust boundaries casually.
- If adding a config key, update `Config` in `config.go`, parsing/merge logic in
  `NewConfig`, runtime wiring in `main.go`, examples, and this document.
- Treat recent high-churn areas as intentional architecture, not cleanup
  targets: the split tunnel client files, raw HTTP/3 reverse tunnel path,
  WireGuard dialer, and TUN forwarding hot path all encode current design
  tradeoffs.
- Keep setup contexts and stream lifetimes separate in tunnel/dialer code where
  the current implementation does so. Do not reattach returned streams to a
  request context that is only meant to bound setup.
- Prefer the current Go 1.26 style already present in the tree (`cmp.Or`,
  `slices`, `maps`, `strings.Lines`, `strings.SplitSeq`, `sync.WaitGroup.Go`)
  where it naturally fits, but do not churn old code just to modernize it.

## Tacit Codebase Conventions

These conventions are inferred from the existing codebase. They are not always
spelled out in comments, but following them keeps new work native to Liner.

### Design intent behind the style

- Liner's essential complexity is external protocol complexity: HTTP/2, HTTP/3,
  QUIC, MASQUE-like tunnels, SOCKS, SSH, DNS, WireGuard, TUN, platform sockets,
  auth tables, shell execution, and operator YAML. The code style intentionally
  avoids adding a second layer of internal framework complexity on top of those
  protocols.
- The repeated Listen -> Handle -> Dial shape is a cognitive compression
  device. After reading one handler or dialer, the next one should look familiar;
  the differences should be real protocol differences, not different local
  architecture.
- Feature files co-locate parsing, auth, policy execution, routing, logging,
  copying, and cleanup so the trust boundary is inspectable in one place. Do not
  split that flow into services or registries unless the existing code already
  proves the boundary is shared.
- Direct control flow is a security and operations choice, not just brevity. It
  makes it clear who owns a `net.Conn`, which context bounds setup, which user
  info authorizes an action, which log fields are emitted, and where credentials
  or command output could leak.
- Config is an operator-facing API. Explicit structs, switches, URL query
  parsing, and manual overlay behavior make compatibility impact visible in a
  diff. Generic config registries or reflective extension systems would hide
  breakage and are out of character here.
- Thin interfaces and standard-library contracts let protocol libraries carry
  wire-format complexity while Liner keeps control over policy, dialing,
  logging, cancellation, and performance boundaries.
- Hot-path code is intentionally mechanical. Buffers, pools, append-style
  parsing, goroutine lifetimes, close paths, and zero-copy conversions should be
  auditable from nearby code. A cleaner abstraction that hides allocation or
  ownership is a regression unless the change is measured and documented.
- Consistent names, file shapes, and even imperfect spellings are part of
  grepability and deployment continuity. They help future patches stay local and
  make accidental cross-protocol behavior changes stand out.
- Before changing code, identify which contract the change touches: wire
  protocol, operator config, auth/trust boundary, log surface, hot path, or
  runtime lifetime. If that cannot be answered from nearby code, read more
  before editing.

### Minimal code style

- Prefer plain Go over framework-style structure. This repository is a compact
  `package main` program with feature files, not a layered enterprise layout.
- Keep code direct. A small local closure, a short helper, or a straightforward
  switch is preferred over a new abstraction when the behavior is used in one
  place.
- Keep feature-local state in feature files. Prefer file-local helpers and
  narrow structs over new exported package-level abstractions.
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
- Follow the existing template pattern: parse templates in `Load(ctx)`, execute
  them against small request-shaped structs in normal paths, and preserve the
  explicit map-based shape used in obfuscated or dynamic paths.
- Parse dialer-template output with the established plain-name, query-string,
  and JSON-object forms. Use `url.ParseQuery` and `json.Unmarshal` rather than
  custom split logic when options are involved.
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

### Compatibility posture

- Be conservative with behavior changes. Liner is configured by YAML, URL
  strings, templates, auth tables, and shell scripts; small parsing changes can
  break deployments.
- Existing config keys, policy return strings, auth attributes, log keys, and
  URL query parameters are compatibility surface.
- Additive changes are safer than semantic changes. If semantics must change,
  document the migration and keep the old path where practical.
- Platform-specific code should stay in platform helpers or guarded runtime
  paths. Unsupported behavior must fail clearly, not silently emulate another
  platform.
- Treat recent high-churn surfaces as intentional architecture, not cleanup
  targets: split tunnel client files, raw HTTP/3 reverse tunnels, WireGuard,
  and the TUN forwarding hot path.

## Design Contracts

This section records concrete contracts that are easy to forget while editing.
The broader style rationale lives above in `Tacit Codebase Conventions`.

### Config Surface

- `NewConfig` manually merges overlays. New top-level fields are not merged
  unless you add that behavior deliberately.
- `@file` expansion is a whitelist, not a generic string-field feature. Extend
  it only for fields that should support file-backed content.
- Validate host, port, prefix, listener, route, and URL inputs with structured
  parsers such as `netip`, `url`, `strconv`, and `net.SplitHostPort`. Use ad
  hoc slicing only for fixed wire formats or measured hot paths.
- Preserve `global.forbid_local_addr` semantics in every new outbound path.
- `cron` is top-level, not under `global`. HTTPS handlers intentionally reject
  `psk`; PSK wrapping belongs on plain HTTP listeners and compatible dialers.
- `tproxy` is Linux-only and uses transparent sockets. TCP original destination
  comes from the accepted local address; UDP requires original-destination
  control messages and transparent reply sockets.

### Dialer Contract

All dialers implement:

```go
type Dialer interface {
    DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}
```

- Named dialers are built line by line in `main.go`, wrapping the previous
  underlay. Do not assume every dialer composes the same way: HTTP/3 currently
  dials QUIC endpoints directly.
- Carry context values consistently: extra HTTP headers, IPv6 disable/prefer
  flags, memory dialers, and memory listeners.

### Template and Policy Outputs

Template output forms used by HTTP, SOCKS, SNI, and TUN dialer selection are
compatibility surface:

```text
proxy1
dialer=proxy1&disable_ipv6=true
{"dialer":"proxy1","prefer_ipv6":true}
```

- Template helpers that read files, write files, fetch URLs, run DNS, or inspect
  GeoIP are policy tools and trust-boundary code.

## Protocol-Specific Constraints

### HTTP and Tunnels

- `HTTPServerHandler` owns request normalization, base64 well-known paths,
  proxy/auth user extraction, trusted real-IP fixes, JA4/user-agent/GeoIP data,
  and dispatch to forward, tunnel, or web handlers.
- `X-Forwarded-For` is trusted only for authenticated proxy users or loopback
  clients. Preserve that boundary.
- HTTP forward policy control strings such as `bypass_auth`, `require_auth`,
  `require_proxy_auth`, `require_www_auth`, `generate_204`, `reject`, `deny`,
  `reset`, `close`, empty, and `proxy_pass` are behavior surface.
- HTTP/3 `CONNECT-UDP` depends on HTTP datagrams and datagram context ID 0.
  Keep client and server `EnableDatagrams` behavior in sync.
- HTTPS `http3_listen` controls both HTTP/3 UDP listeners and the Alt-Svc
  advertised port. When omitted or all entries are empty, Alt-Svc uses the TCP
  port unchanged (zero intrusion on existing behavior). A single non-empty value
  is shared by all TCP listeners; values matching `listen` length are positional,
  and an empty positional value means that position keeps its TCP port. The
  Alt-Svc override map only stores entries where the UDP port differs from the
  TCP port.
- HTTP/3 dialer `udp_port` query parameter (e.g.,
  `http3://host:443/?udp_port=8443`) tells the QUIC dialer to connect on a
  different port than the URL port. When omitted, the dialer uses the URL port
  (default 443). This is the client-side counterpart of server-side `http3_listen`.
- HTTP/1.1 and HTTP/2 reverse tunnels use yamux over the request stream.
  HTTP/3 reverse tunnels use raw QUIC streams with `HTTP3TunnelOpenFrame`.
  Do not merge those paths casually.
- Server-side HTTP/3 reverse tunnel auth and `allow_listens` checks stay in
  `HTTPTunnelHandler`, sharing the same trust boundary as HTTP/1.1 and HTTP/2.
- Top-level `tunnel` is the remote client. Server-side reverse tunnels are
  configured under `http[].tunnel` or `https[].tunnel`.
- `remote_listen` currently expects exactly one address in `TunnelHandler.Load`.

### SOCKS, DNS, SNI, Stream, SSH

- SOCKS server support is SOCKS5. Non-SOCKS5 server commands are rejected
  explicitly. SOCKS UDP ASSOCIATE is per-association, reuses one upstream UDP
  connection per target, ignores fragmentation, and is bounded by
  `socks[].forward.udp_timeout`.
- Standalone DNS listeners are UDP, TCP, or TLS-wrapped TCP. DoH is exposed
  through HTTP web `doh`; DoH/DoH3 are upstream resolver schemes.
- DNS policy directives include `HOST`, `CNAME`, `TXT`, `ERROR`, and
  `PROXY_PASS`. Preserve packet-pool reuse and response-writer contracts.
- SNI routing inspects ClientHello without terminating TLS and forwards the
  mirrored header bytes to the selected upstream. Keep `ErrTLSServerNameHijacked`
  behavior intact.
- SSH shell, exec, SFTP, env, direct-tcpip, authorized keys, auth tables, and
  `shell: "$"` GOSH re-entry are command/trust-boundary code. Be deliberate
  about environment inheritance and logged command data.

### Redsocks and TProxy

- `redsocks` is for TCP transparent REDIRECT/rdr paths that recover the
  original destination through platform socket APIs.
- `tproxy` is Linux-only. Its listeners must set transparent socket options;
  UDP handling must preserve the original destination as the source address
  when writing packets back to the intercepted client.

### TUN

`handler_tun.go` is a hot path. Read it and the target platform helper before
touching TUN behavior.

- The gVisor stack, high default MTU, batched device I/O, reusable copy buffers,
  packet headroom reuse, and no-GSO shape are intentional throughput choices.
- Default address is `198.18.0.1/15`; default MTU is high (`9000`, lower on
  macOS). Do not reduce throughput defaults as cleanup.
- `routes` entries beginning with `-` are bypass routes. `0.0.0.0/0` is split
  into `/1` routes, and IPv6 split defaults are added when IPv6 forwarding is
  disabled so IPv6 traffic reaches the reject path instead of escaping.
- Bypass route generation includes configured dialer endpoints and DNS resolver
  endpoints. Keep platform helper behavior in sync when route semantics change.
- Windows adds a high-metric default route when routes are empty so
  source-bound clients can select the TUN without replacing normal routing.
- DNS on port 53 is intercepted and sent through `tun.dns_server` when set. If
  TUN IPv6 is disabled, intercepted AAAA queries return empty NoError locally.
- `tun[].disable_udp` drops non-DNS UDP forwarding when true; UDP DNS on
  port 53 still uses the TUN DNS interception path when configured.
- `tun[].forward.process_dialer` matches `.ProcessInfo.Path` regexes in order
  before the normal `forward.dialer` template/static selection. Compile regexes
  and validate dialers in `Load(ctx)`. When no process rule or dialer selects
  an upstream, TUN forwarding falls back to local.
- TUN forwarding rejects unspecified, multicast, limited broadcast, and
  destinations inside the configured TUN address prefix.
- Dial timeouts in TUN are setup-only; do not bind stream lifetime to setup
  context by accident.
- `tun[].forward.tcp_timeout` is TCP stream idle timeout in seconds. `0`
  means the default `600`; a negative value disables idle timeout.

### WireGuard

- WireGuard is a first-class dialer backed by userspace `tun/netstack`.
- It lazily initializes from `wg-quick` style config URLs such as
  `wg:///etc/wireguard/wg0.conf`.
- It supports TCP and UDP, honors DNS plus IPv4/IPv6 preference where
  applicable, and must reject address-family mismatches clearly.

## Hot Path and Low-Level Code

- Allocation awareness matters in DNS, HTTP copy paths, TUN, TLS inspection,
  SOCKS UDP, and helpers.
- Preserve append-style builders (`AppendableBytes`, `AppendReadFrom`),
  zero-copy conversions (`b2s`, `s2b`), `bytebufferpool`, `sync.Pool`, reusable
  DNS request objects, and TUN copy-buffer pools unless you measure and justify
  a replacement.
- Do not wrap hot-path ownership or allocation behavior in a cleaner abstraction
  that hides who owns buffers, deadlines, goroutines, or connections.
- Reflection and `unsafe` are used in narrow places for compatibility or
  performance. Do not spread them as a general extension mechanism.
- Keep connection reuse for HTTP/2, HTTP/3, QUIC, SSH, DNS, yamux, and
  WireGuard netstack state.
- Avoid global locks in forwarding paths unless the impact is isolated or
  measured.

## Logging and Errors

- Use `github.com/phuslu/log` structured logging and stable field names already
  present in nearby code: `trace_id`, `server_addr`, `remote_ip`, `req_host`,
  `forward_dialer_name`, `dns_server`, `tun_name`, and similar local keys.
- Log routing decisions with enough context to debug selected policy, selected
  dialer, user, host/port, network, and config name.
- Do not copy permissive header/body logging from one protocol into another.
  Some existing debug paths are broad; new code should be tighter.
- Return errors across boundaries with context (`fmt.Errorf("...: %w", err)`).
  Startup wiring in `main.go` commonly logs fatal after `Load` or listener setup
  failures.
- Platform unsupported behavior should be explicit, commonly
  `errors.ErrUnsupported`, not silent emulation.

## Platform Code

- Keep OS behavior in build-tagged platform helpers unless the current code has
  a runtime guard.
- Linux, macOS, Windows, and fallback helpers intentionally differ for socket
  binding, original-destination lookup, TUN routes, TCP info, TCP congestion,
  process lookup, process naming, and terminal handling.
- When route, TUN, socket option, process lookup, or TCP pacing behavior changes
  on one OS, inspect the others and update them or leave an explicit unsupported
  path.
- Privileged features such as TUN, redsocks, tproxy, tcp-brutal, route changes, and
  platform socket options may require manual validation. Do not claim full
  coverage from `go test` alone.
- Keep c-shared entry points and build constraints intact in `liner-dll.go` and
  `liner-py.go`.

## Change Checklists

### Config Key

1. Add the field to the correct struct in `config.go`.
2. Decide and implement overlay merge behavior in `NewConfig`.
3. Decide whether `@file` expansion applies.
4. Wire construction in `main.go` or the owning `Load(ctx)`.
5. Update examples and this file when the operator-facing contract changes.

### Dialer

1. Study the closest dialer and preserve `DialContext` semantics.
2. Parse URL options through `url.Query()`.
3. Respect context cancellation, memory dialers, DNS resolver, TLS cache, IPv6
   flags, and underlay composition where applicable.
4. Register the scheme in `main.go`.
5. Return `errors.ErrUnsupported` for unsupported networks.

### Handler

1. Study a handler with the same lifecycle shape.
2. Put validation, auth loader setup, template parsing, and stable caches in
   `Load(ctx)`.
3. Keep protocol parsing, auth, policy, dialing, logging, and copying in the
   feature file unless an existing helper already owns that exact contract.
4. Wire listeners and construction in `main.go`.
5. Add focused tests or manual validation notes according to risk.

### Template Helper

1. Implement the method in `functions.go`.
2. Register it in `Functions.Load`.
3. Use existing caches for repeated DNS, regex, fetch, GeoIP, or file work.
4. Document trust-boundary behavior if it reads files, writes files, fetches
   URLs, or exposes request/process data.

## Validation

Use targeted tests for narrow changes and broader tests for shared contracts.
Common commands:

```bash
gofmt -w <changed-go-files>
go test ./...
go test ./... -count=1
go build -v
```

If the Go build cache is not writable, use a cache under `/tmp`, for example:

```bash
GOCACHE=/tmp/liner-go-build go test ./...
```

Network resolver tests, TUN, redsocks, tproxy, tcp-brutal, route configuration, and
privileged socket behavior may need network access, platform support, or
elevated privileges.

## Things to Ignore Unless Asked

Local runtime artifacts such as `liner`, `*.log`, `data.*.log`, `autocert/`,
`lego/`, `.codex/`, local YAML files, and generated archives may exist in the
worktree. Do not edit or delete them unless the task explicitly targets runtime
state.
