# AGENTS.md - Liner

This file applies to the whole repository. It records principles and tastes
that are hard to infer from the code alone. For facts about current behavior,
read the code; if this file and the code disagree, trust the code first, then
update this file in the same change.

## Shape and Intent

Liner is a compact `package main` Go proxy built around one repeated pipeline:

```text
listener accepts -> handler authenticates, classifies, routes, logs, copies -> dialer opens upstream
```

- The essential complexity is external protocol complexity (HTTP/1-3, QUIC,
  MASQUE, SOCKS, SSH, DNS, TUN, platform sockets, auth tables, operator YAML).
  Do not add a second layer of internal framework complexity on top of it.
- The repeated Listen -> Handle -> Dial shape is a cognitive compression
  device. After reading one handler or dialer, the next should look familiar;
  differences should be real protocol differences, not different local
  architecture.
- Feature files co-locate parsing, auth, policy, routing, logging, copying, and
  cleanup so the trust boundary is inspectable in one place. Do not split that
  flow into services or registries.
- Direct control flow is a security and operations choice: it keeps visible who
  owns a `net.Conn`, which context bounds setup, which user info authorizes an
  action, which log fields are emitted, and where secrets could leak.
- Before changing code, name the contract it touches: wire protocol, operator
  config, auth/trust boundary, log surface, hot path, or runtime lifetime. If
  that cannot be answered from nearby code, read more before editing.

## Code Style

- Plain Go, feature files (`handler_<feature>.go`, `dialer_<protocol>.go`), no
  package directories for a narrow feature.
- Prefer a small closure, short helper, or straightforward switch over a new
  abstraction. No service objects, registries, builders, option structs, or
  interfaces unless polymorphism is already needed at that point.
- Duplication is deliberate. Per-handler dialer selection blocks, per-OS copies
  of shared types and functions, the stream `net.Conn` wrappers, yamux/QUIC
  tuning literals (with different knobs per site), and full log chains at each
  reject site are copied on purpose. Do not "clean up" by merging them into a
  shared helper; copy the closest one when adding a new site.
- Interfaces stay tiny and standard-library shaped (`Dialer` is one method).
- Keep feature state on the handler/dialer struct; avoid new package globals
  and new exported names without a practical reason.
- Short names in tight scopes (`h`, `d`, `req`, `ri`, `u`, `ln`, `conn`,
  `rconn`, `lconn`), descriptive at module boundaries.
- Comments are sparse and functional: unsafe tricks, protocol references,
  platform behavior, performance constraints, non-obvious security decisions.
  Do not narrate ordinary Go.
- Early returns over nested branches.
- Match existing spelling and naming even when imperfect (for example the
  `invaild` in `Load` errors); grepability and deployment continuity beat
  opportunistic cleanup.
- Use existing helpers (`cmp.Or`, `first`, `must`, `lru`, `xsync.Map`,
  `FileLoader`, `NewCachingMap`) instead of introducing competing ones. Prefer
  Go 1.26+ idioms where they fit naturally, but do not churn old code to
  modernize it.
- Do not add dependencies without a clear reason.

## Implementation Taste

- Configuration drives behavior: new features appear as config fields,
  templates, URL query parameters, or auth attributes before hard-coded policy.
- URL schemes are the extension mechanism for dialers and DNS resolvers; prefer
  a scheme switch over a generic framework.
- Handlers do fail-fast work in `Load` (validation, template parsing, regex
  compilation, auth loaders, caches). HTTP-family, SOCKS, SSH, and TUN take
  `Load(ctx)`; DNS, SNI, stream, redsocks, tproxy, and tunnel take `Load()`.
  Follow the neighbor. Request paths must not re-parse stable config.
- Runtime wiring belongs in `main.go` unless a more local construction point
  already exists.
- Defaults live at the point of use, never in a defaults table: zero means
  default, written as `cmp.Or(query, config, literal)`. Durations are integer
  seconds; a negative value usually disables the feature.
- Parse with structured parsers (`netip`, `net`, `url`, `strconv`,
  `net.SplitHostPort`); ad hoc slicing only for fixed wire formats or measured
  hot paths. Dialer-template options go through `url.ParseQuery` /
  `json.Unmarshal`, not custom splitting.
- Treat the split tunnel client files, raw HTTP/3 reverse tunnel path, and TUN
  forwarding hot path as intentional architecture, not cleanup targets.

## Templates

- Every template execution builds its data twice:
  `if obfuscated { map[string]any{...} } else { struct{...} }`. Garble builds
  rename struct fields, which breaks template field lookup, so the map branch
  is required. A new template field must be added to both branches with the
  same name.
- Template data field names are a fixed vocabulary taken from the request
  info: `Request`, `RealIP`, `ClientHelloInfo`, `JA4`, `UserAgent`,
  `ServerAddr`, `User`. Reuse these names; do not invent synonyms.
- Each handler carries its own copy of the dialer selection block: JSON when
  output starts with `{"`, `url.ParseQuery` when it contains `=`, otherwise a
  plain dialer name; empty name falls back to `LocalDialer`; IPv6 flags go into
  ctx (disable before prefer), then forwarded headers. Copy it, do not abstract
  it.
- Dialer template output forms are compatibility surface:

  ```text
  proxy1
  dialer=proxy1&disable_ipv6=true
  {"dialer":"proxy1","prefer_ipv6":true}
  ```

  Transparent handlers (redsocks, tproxy) also accept `dialer-addrport-context`
  to override the dial target.

## Dialers

- Dialers have no `Load`. Expensive state is built lazily on the first
  `DialContext`: static state behind a mutex, live sessions in an
  `atomic.Pointer` with a double-checked mutex. Clear a cached session with
  CompareAndSwap only if it is still the same session.
- Proxy dialers check `MemoryDialerOf(ctx, ...)` first and dial memory
  addresses directly, before any underlay or proxy handshake.
- Separate setup from stream lifetime with this idiom:
  `streamCtx, streamCancel := context.WithCancel(context.WithoutCancel(ctx))`
  plus `stop := context.AfterFunc(ctx, streamCancel)`; after setup, `!stop()`
  means setup was cancelled, so tear down and return. Never bind a returned
  stream to a context that only bounds setup.
- TUN discovers bypass routes by reflecting over dialer fields named `Host`,
  `Resolve`, and `Dialer` (the underlay chain). Keep those field names in every
  dialer; renaming them silently loses the bypass route and can create a
  routing loop.
- Only `LocalDialer` enforces `global.forbid_local_addr` and the configured
  DNS resolver. New outbound paths must go through `LocalDialer`. Known gaps
  today: the HTTP/3 dialer, the tunnel HTTP/3 dial, and DoH/DoH3 transports
  dial directly.
- Carry context values (extra headers, IPv6 flags, memory dialers/listeners)
  consistently through new dialers. Not every dialer composes the same way
  (HTTP/3 dials QUIC directly).

## Compatibility

- Config keys, policy return strings, auth attributes, log keys, URL query
  parameters, and template output forms are compatibility surface. The YAML is
  an operator-facing API; keep it explicit rather than abstract.
- Additive changes over semantic changes. If semantics must change, document
  the migration and keep the old path where practical.
- `NewConfig` merges overlays manually: a new top-level field is not merged
  unless you add it. `@file` expansion is a whitelist, not a generic feature.
- HTTP forward policy strings beyond the explicit cases (for example
  `verify_auth` used in `example.yaml` and `get.sh`) rely on "anything other
  than `bypass_auth` requires auth". Keep that fallthrough.

## Trust Boundaries

- Command execution and file/network helpers are high risk: `cron.command`,
  auth command loaders/checkers, template `fetch`/`readfile`/`savefile`, web
  shell, SSH shell/exec/env, and deployment scripts must not expand trust
  boundaries casually.
- Never log secrets: auth headers, PSKs, private keys, passwords, password
  hashes, cookies, and user command output need deliberate redaction or
  omission. Some existing debug logging is broad; do not copy it into new
  protocols.
- Auth attributes are strings: `"1"` allows, `"0"` denies, `"-1"` means
  privileged (no limit, skips listen checks). Gate attributes are named
  `allow_<feature>`.
- `Attrs` exist only after `CheckAuthUser` succeeds, because it overwrites the
  user with the stored record. Check first, then read attributes; never compare
  `user.Password` after the check.
- Client-facing failures stay terse and unfingerprintable: failed proxy auth
  goes through `RejectRequest` (random 1-3s delay, then 400, not 403); policy
  rejection or unknown dialer returns 404; upstream or dial failure returns
  502.
- `X-Forwarded-For` is trusted only for authenticated proxy users or loopback
  clients.
- HTTPS handlers intentionally reject `psk`; PSK wrapping belongs to plain HTTP
  listeners and compatible dialers.
- HTTP/3 reverse tunnel auth and `allow_listens` checks stay in
  `HTTPTunnelHandler`, sharing the trust boundary with HTTP/1.1 and HTTP/2.
- SSH client environment is allow-listed; other variables must never reach the
  session.

## Request Lifetime

- `HTTPRequestInfo` (`ri`) is pooled. Never retain it after `ServeHTTP`
  returns or capture it in a goroutine that outlives the request. A new `ri`
  field must be reset explicitly in the per-request reset code.
- Look up process info at most once per connection (`sync.Once`) and return
  nil when it is unavailable. Do not retry or sleep in the handler; that
  approach was tried and reverted.

## Protocol Invariants Easy to Break

- HTTP/1.1 and HTTP/2 reverse tunnels use yamux; HTTP/3 uses raw QUIC streams.
  Do not merge those paths.
- HTTP/3 `CONNECT-UDP` relies on datagrams; keep client and server
  `EnableDatagrams` in sync.
- SNI routing must not terminate TLS; keep `ErrTLSServerNameHijacked` intact.
- TUN throughput choices (gVisor stack with gVisor GSO, high default MTU,
  batched I/O, buffer and headroom reuse) are deliberate. Do not reduce
  defaults as cleanup. TUN dial timeouts are setup-only.

## Hot Paths

- DNS, HTTP copy, TUN, TLS inspection, SOCKS UDP, and helpers are allocation
  sensitive. Preserve `AppendableBytes`, `AppendReadFrom`, `b2s`/`s2b`,
  `bytebufferpool`, `sync.Pool`, DNS request reuse, and TUN buffer pools unless
  you measure and justify a replacement.
- Idle timers on hot paths use an atomic last-activity `touch` with a lazily
  re-armed timer. Never call `SetDeadline` or `Timer.Reset` per packet.
- A cleaner abstraction that hides who owns buffers, deadlines, goroutines, or
  connections is a regression.
- Keep connection reuse (HTTP/2, HTTP/3, QUIC, SSH, DNS, yamux).
- No global locks in forwarding paths unless isolated or measured.
- `reflect` and `unsafe` stay in narrow places; do not spread them.

## Logging and Errors

- Logger by layer: handlers use the global `github.com/phuslu/log`; resolvers
  hold a phuslu `*log.Logger`; dialers hold an optional `*slog.Logger` and
  nil-check it; SSH uses its injected `h.Logger`. Follow the layer you are in.
- Two channels: operational logs use the global logger (`remote_ip` is the
  address only, no port); per-connection records go to `h.DataLogger` starting
  with `Str("logger", "<proto>")`, ending with `.Msg("")`, gated by the
  handler's `Log` config, and written when the connection finishes.
- Reuse the stable field names already used nearby (`trace_id`,
  `server_addr`, `remote_ip`, `forward_dialer_name`, `tun_name`, ...). Log
  routing decisions with enough context to debug: policy, dialer, user,
  host/port, network, config name.
- Handlers wrap errors with `fmt.Errorf("...: %w", err)`. Dialers use a fixed
  lowercase prefix (`httpdialer:`, `socksdialer:`, ...); follow the local file.
- Unsupported behavior fails explicitly (commonly `errors.ErrUnsupported`),
  never silently emulates another platform.

## Platform Code

- OS behavior lives in build-tagged platform helpers unless a runtime guard
  already exists.
- `_zzz.go` with `//go:build !darwin && !linux && !windows` is the
  unsupported-OS fallback returning `errors.ErrUnsupported`. `_others.go` with
  `//go:build !<os>` is used when only one OS is special and the rest share a
  pass-through. Private platform helpers carry an OS prefix
  (`linuxGetOriginalDST`).
- When route, TUN, socket option, process lookup, or TCP pacing behavior
  changes on one OS, inspect the others and update them or leave an explicit
  unsupported path.
- Privileged features (TUN, redsocks, tproxy, tcp-brutal, routes, socket
  options) need manual validation; do not claim coverage from `go test` alone.
- Keep c-shared entry points and build constraints in `liner-dll.go` and
  `liner-py.go` intact.

## Checklists

Config key: field in `config.go` -> overlay merge in `NewConfig` -> decide
`@file` -> wire in `main.go` or `Load` -> update examples.

Dialer: follow the closest dialer -> options via `url.Query()` -> memory dialer
check, lazy init, cancellation, resolver, TLS cache, IPv6 flags, underlay, keep
`Host`/`Resolve`/`Dialer` names -> register scheme in `main.go` ->
`errors.ErrUnsupported` for unsupported networks.

Template helper: implement in `functions.go` -> register in `Functions.Load`
-> use existing caches -> document trust-boundary behavior if it touches files,
URLs, or request/process data.
