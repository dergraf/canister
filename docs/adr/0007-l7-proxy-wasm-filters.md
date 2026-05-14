# ADR-0007: L7 Egress Proxy with Wasm Filters

## Status
Accepted

## Date
2026-05-14

## Context

Seccomp + USER_NOTIF (ADR-0003) enforces network policy at the *syscall*
level: a `connect()` to a non-allowed IP is denied with `EPERM`. This is
sufficient for IP-allowlist policies, but it has three structural limits:

1. **No L7 visibility.** A connect to an HTTPS API is allowed/denied as
   one bit ("can the process reach this IP?"). Whether the request body
   contains an API key, hits a forbidden path, or carries a header that
   should be rewritten is invisible at the syscall layer.

2. **Coarse for shared hosts.** Many APIs are served behind the same
   CDN IP (Cloudflare, Fastly). Allowing the IP means allowing every
   tenant on the CDN, not just the intended API.

3. **No mutation.** Defensive uses ("strip `Authorization` from outbound
   requests to a third-party CI runner", "redact tokens in URLs that get
   logged upstream") require modifying the request, which a syscall-layer
   filter cannot do.

Linux sandboxes have historically solved this with one of:

- An external sidecar proxy (Envoy, Nginx) with the sandbox's traffic
  routed through it via iptables. Requires root for iptables, breaks the
  unprivileged-by-design constraint.
- A `LD_PRELOAD` shim that intercepts `connect()` in libc. Trivially
  bypassed by any process that calls the syscall directly.
- A purpose-built HTTP proxy that the sandbox's traffic is *forced*
  through by the surrounding network policy.

The third option is the only one compatible with canister's
unprivileged-by-design model. We had already designed the seccomp filter
to deny direct outbound connects in `proxy-only` mode (ADR-0006); now we
needed the proxy itself, plus a way for users to extend it without
recompiling canister.

## Options Considered

### Option 1: Static built-in filters only

**Description**: Ship a fixed set of filter behaviors (allow-list-by-host,
strip auth headers, etc.) compiled into the `can` binary. Users opt in
via recipe.

**Pros**:
- Simplest implementation. No plugin runtime.
- No supply-chain concerns about user-provided filter code.

**Cons**:
- Closed extensibility — every new filter capability needs a release of
  canister.
- Forces the project to opinionate on filter logic (e.g., "is rewriting
  paths in URL query strings in-scope?").
- Locks users out of domain-specific filters they could write themselves
  in a few lines.

**Estimated effort**: Low

### Option 2: proxy-wasm (Envoy ABI)

**Description**: Implement the proxy-wasm ABI, which Envoy uses for its
Wasm filters. Users author filters in Rust/AssemblyScript/Go against the
existing proxy-wasm SDKs.

**Pros**:
- Reuses Envoy's mature filter ecosystem.
- Familiar to anyone who has written an Envoy filter.

**Cons**:
- proxy-wasm is tightly coupled to Envoy's HTTP filter chain semantics
  (Action::Continue / Pause / StopAndBuffer, etc.). Mapping it onto our
  much simpler `hyper`-based pipeline introduces semantic gaps that
  break filter portability anyway.
- proxy-wasm assumes a long-lived filter instance per connection with
  cooperative cancellation. Our model is request-scoped.
- The proxy-wasm SDKs are heavy and have non-trivial wasm runtime
  requirements (e.g., specific exports the host must provide).

**Estimated effort**: High

### Option 3: ExtProc-style ABI on Extism

**Description**: Define a small, request-scoped Wasm ABI inspired by
Envoy's ExtProc external-processor protocol: synchronous calls into
`on_request_headers`, `on_request_body`, `on_response_headers`,
`on_response_body`, plus optional trailer hooks. The host serializes the
request fragment to JSON, the plugin returns a JSON action document
(`Continue` + optional header/body mutations). Run plugins on Extism, a
self-contained Wasm runtime built on Wasmtime.

**Pros**:
- ABI is minimal (six JSON-shaped functions). The full spec fits in
  `docs/wasm-abi.md`.
- Maps cleanly onto our request-scoped, body-streaming `hyper` proxy.
- Extism owns the Wasm sandbox and gives us `CancelHandle` for free —
  load-bearing for the per-hook timeout (`wasm_hook_timeout_ms`).
- Plugins are easy to author: any language with serde-JSON support can
  return the action document. The reference test plugin (`tests/
  fixtures/test-plugin`) is ~150 lines of Rust.

**Cons**:
- A custom ABI is one more thing for users to learn. Mitigated by the
  surface being tiny.
- JSON serialization per hook is more overhead than a binary ABI. In
  practice the bodies are bounded by `max_buffered_body_bytes` (default
  8 MiB), and hook timeouts (default 200 ms) cap worst-case latency.

**Estimated effort**: Medium

## Decision

**Option 3.** Commit `c79151f` ("feat(proxy): Add L7 proxy with Wasm
execution and TCP/HTTP passthrough") landed the proxy + ABI. Commit
`89212c3` ("docs: Add Wasm ABI specification for ExtProc style")
documented the contract. `docs/wasm-abi.md` is the canonical spec.

The runtime is Extism (`extism = "1"`), wrapping Wasmtime. Each plugin is
loaded once at proxy startup with one shared `Plugin` instance per
domain, guarded by `parking_lot::Mutex` to allow safe cancellation
without poisoning the lock. Cancellation is via Extism's `CancelHandle`,
driven from a watchdog thread armed before each call.

The proxy is positioned downstream of the namespace's loopback and
upstream of the upstream socket: traffic from the sandboxed process
hits the proxy because the seccomp `connect()` filter denies all
non-proxy egress in `EgressMode::ProxyOnly` (ADR-0006). HTTPS is
intercepted via dynamic CA (`DynamicCa`) — the sandbox trusts the proxy
CA by default; recipes that need true end-to-end TLS use
`EgressMode::Direct`.

## Consequences

### Positive
- Users can ship domain-specific filtering policy (e.g., "redact this
  one query parameter on requests to api.example.com") without
  rebuilding canister.
- The ABI is small enough that contributors can read it once and write
  a filter the same afternoon. The reference test plugin doubles as a
  worked example.
- All hardening lives in one place (the proxy crate): body caps, hook
  timeouts, CRLF rejection, content-length recomputation, upstream
  timeouts. Filters cannot accidentally weaken any of these — the host
  enforces them after the plugin returns its mutations.
- The CancelHandle approach gives us reliable timeout enforcement even
  for compute-bound (non-yielding) plugin loops; tested by
  `t_wasm_hook_timeout_returns_502_in_strict_mode`.

### Negative
- HTTPS interception requires installing the proxy CA in the sandbox.
  Recipes that need to talk to certificate-pinning APIs cannot use
  Wasm filters on that domain — they must use `EgressMode::Direct` for
  that destination and accept the loss of L7 visibility there.
- Plugins are trusted code: they run in the proxy's process. Extism's
  Wasm sandbox bounds memory access, but a malicious plugin can still
  burn CPU up to the configured timeout and consume up to
  `max_buffered_body_bytes` of memory per concurrent request. Filters
  should be authored or audited like any other proxy code.
- The strict-mode policy ("plugin error → fail closed with 502") is a
  hard split from the streaming-body stage, where we can't fail
  closed after headers are sent. Documented in `handle_wasm_hook_error`
  but is a surprise for anyone who expects strict to be uniform.

### Neutral
- The `experimental-h2c` feature flag is wired but disabled by default
  while we stabilize HTTP/2 upstream forwarding. See the
  `#[cfg_attr(..., ignore = "...")]` on the h2c integration test.

## Follow-up Actions
- [x] Document the ABI (`docs/wasm-abi.md`).
- [x] Land per-hook timeout, body caps, CRLF rejection, content-length
      handling, upstream timeout (Phase 1 hardening, this branch).
- [x] Integration tests for body limits, Wasm timeout, strict-mode
      plugin errors, CRLF smuggling (this branch).
- [ ] Pool plugin instances per filter so concurrent requests don't
      serialize on the single per-domain mutex. (Currently the bound is
      the per-request hook duration × concurrency; acceptable until we
      see contention in practice.)
- [ ] Stabilise h2c upstream forwarding and remove the
      `experimental-h2c` feature flag.
- [ ] Investigate proxy-wasm compatibility shim if the ecosystem demand
      materialises — not currently planned.
