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
  MASQUE, SOCKS, SSH, DNS, WireGuard, TUN, platform sockets, auth tables,
  operator YAML). Do not add a second layer of internal framework complexity on
  top of it.
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
- Interfaces stay tiny and standard-library shaped (`Dialer` is one method;
  handlers are `http.Handler` plus `Load(ctx)`).
- Keep feature state on the handler/dialer struct; avoid new package globals
  and new exported names without a practical reason.
- Short names in tight scopes (`h`, `d`, `req`, `ri`, `u`, `ln`, `conn`,
  `rconn`, `lconn`), descriptive at module boundaries.
- Comments are sparse and functional: unsafe tricks, protocol references,
  platform behavior, performance constraints, non-obvious security decisions.
  Do not narrate ordinary Go.
- Early returns over nested branches.
- Match existing spelling and naming even when imperfect; grepability and
  deployment continuity beat opportunistic cleanup.
- Use existing helpers (`cmp.Or`, `first`, `must`, `lru`, `xsync.Map`,
  `FileLoader`, `NewCachingMap`) instead of introducing competing ones. Prefer
  Go 1.26 idioms where they fit naturally, but do not churn old code to
  modernize it.
- Do not add dependencies without a clear reason.

## Implementation Taste

- Configuration drives behavior: new features appear as config fields,
  templates, URL query parameters, or auth attributes before hard-coded policy.
- URL schemes are the extension mechanism for dialers and DNS resolvers; prefer
  a scheme switch over a generic framework.
- `Load(ctx)` does fail-fast work (validation, template parsing, regex
  compilation, auth loaders, caches). Request paths must not re-parse stable
  config.
- Runtime wiring belongs in `main.go` unless a more local construction point
  already exists.
- Parse with structured parsers (`netip`, `net`, `url`, `strconv`,
  `net.SplitHostPort`); ad hoc slicing only for fixed wire formats or measured
  hot paths. Dialer-template options go through `url.ParseQuery` /
  `json.Unmarshal`, not custom splitting.
- Keep setup contexts and stream lifetimes separate. Never bind a returned
  stream to a context that is only meant to bound setup.
- Treat the split tunnel client files, raw HTTP/3 reverse tunnel path,
  WireGuard dialer, and TUN forwarding hot path as intentional architecture,
  not cleanup targets.

## Compatibility

- Config keys, policy return strings, auth attributes, log keys, URL query
  parameters, and template output forms are compatibility surface. The YAML is
  an operator-facing API; keep it explicit rather than abstract.
- Additive changes over semantic changes. If semantics must change, document
  the migration and keep the old path where practical.
- `NewConfig` merges overlays manually: a new top-level field is not merged
  unless you add it. `@file` expansion is a whitelist, not a generic feature.
- Preserve `global.forbid_local_addr` in every new outbound path.
- Dialer template output accepts all three forms; keep them working:

  ```text
  proxy1
  dialer=proxy1&disable_ipv6=true
  {"dialer":"proxy1","prefer_ipv6":true}
  ```

## Trust Boundaries

- Command execution and file/network helpers are high risk: `cron.command`,
  auth command loaders/checkers, template `fetch`/`readfile`/`savefile`, web
  shell, SSH shell/exec/env, and deployment scripts must not expand trust
  boundaries casually.
- Never log secrets: auth headers, PSKs, private keys, passwords, cookies, and
  user command output need deliberate redaction or omission. Some existing
  debug logging is broad; do not copy it into new protocols.
- `X-Forwarded-For` is trusted only for authenticated proxy users or loopback
  clients.
- HTTPS handlers intentionally reject `psk`; PSK wrapping belongs to plain HTTP
  listeners and compatible dialers.
- HTTP/3 reverse tunnel auth and `allow_listens` checks stay in
  `HTTPTunnelHandler`, sharing the trust boundary with HTTP/1.1 and HTTP/2.
- SSH client environment is allow-listed; other variables must never reach the
  session.

## Protocol Invariants Easy to Break

- HTTP/1.1 and HTTP/2 reverse tunnels use yamux; HTTP/3 uses raw QUIC streams.
  Do not merge those paths.
- HTTP/3 `CONNECT-UDP` relies on datagrams; keep client and server
  `EnableDatagrams` in sync.
- Not every dialer composes the same way (HTTP/3 dials QUIC directly). Carry
  context values (extra headers, IPv6 flags, memory dialers/listeners)
  consistently through new dialers.
- SNI routing must not terminate TLS; keep `ErrTLSServerNameHijacked` intact.
- TUN throughput choices (gVisor stack, high default MTU, batched I/O, buffer
  and headroom reuse, no GSO) are deliberate. Do not reduce defaults as
  cleanup. TUN dial timeouts are setup-only.

## Hot Paths

- DNS, HTTP copy, TUN, TLS inspection, SOCKS UDP, and helpers are allocation
  sensitive. Preserve `AppendableBytes`, `AppendReadFrom`, `b2s`/`s2b`,
  `bytebufferpool`, `sync.Pool`, DNS request reuse, and TUN buffer pools unless
  you measure and justify a replacement.
- A cleaner abstraction that hides who owns buffers, deadlines, goroutines, or
  connections is a regression.
- Keep connection reuse (HTTP/2, HTTP/3, QUIC, SSH, DNS, yamux, WireGuard).
- No global locks in forwarding paths unless isolated or measured.
- `reflect` and `unsafe` stay in narrow places; do not spread them.

## Logging and Errors

- Use `github.com/phuslu/log` with the stable field names already used nearby.
- Log routing decisions with enough context to debug: policy, dialer, user,
  host/port, network, config name.
- Wrap errors across boundaries with `fmt.Errorf("...: %w", err)`.
- Unsupported behavior fails explicitly (commonly `errors.ErrUnsupported`),
  never silently emulates another platform.

## Platform Code

- OS behavior lives in build-tagged platform helpers unless a runtime guard
  already exists.
- When route, TUN, socket option, process lookup, or TCP pacing behavior
  changes on one OS, inspect the others and update them or leave an explicit
  unsupported path.
- Privileged features (TUN, redsocks, tproxy, tcp-brutal, routes, socket
  options) need manual validation; do not claim coverage from `go test` alone.
- Keep c-shared entry points and build constraints in `liner-dll.go` and
  `liner-py.go` intact.

## Checklists

Config key: field in `config.go` -> overlay merge in `NewConfig` -> decide
`@file` -> wire in `main.go` or `Load(ctx)` -> update examples.

Dialer: follow the closest dialer -> options via `url.Query()` -> respect
cancellation, memory dialers, resolver, TLS cache, IPv6 flags, underlay ->
register scheme in `main.go` -> `errors.ErrUnsupported` for unsupported
networks.

Template helper: implement in `functions.go` -> register in `Functions.Load`
-> use existing caches -> document trust-boundary behavior if it touches files,
URLs, or request/process data.

## Validation

```bash
gofmt -w <changed-go-files>
go test ./...
go build -v
```

If the build cache is not writable, use `GOCACHE=/tmp/liner-go-build`.
Documentation-only edits need no Go tests.

## Leave Alone Unless Asked

Local runtime artifacts: `liner`, `*.log`, `data.*.log`, `autocert/`, `lego/`,
`.codex/`, local YAML files, generated archives. Preserve uncommitted user work
in a dirty tree.
