# Proxy Forwarding Implementation Plan (L7 Semantic Forwarder)

This plan formalizes the simplification strategy for Canister proxy forwarding:

- Keep `CONNECT + MITM` for HTTPS interception.
- Use a real HTTP server/client forwarding model (L7 semantic forwarding).
- Do not target byte-for-byte transparency.

## Contract

### What is preserved

- HTTP method, authority, path/query semantics.
- Header/body/trailer interception lifecycle for Wasm plugins.
- Policy enforcement (`allow_domains`/`allow_ips`) before outbound dialing.
- Seccomp USER_NOTIF first-line outbound gate before user-space forwarding.

### What may change

- Hop-by-hop headers are normalized/removed.
- Transfer framing may change (`chunked` vs `content-length`) after mutation or buffering.
- HTTP version at egress may differ if transport policy requires it.

### Signature-aware behavior

No cloud/vendor-specific signature logic is embedded in Rust forwarding code.
Signature-safe behavior (inspection-only, forced buffering, re-signing) must be implemented via Wasm plugin policy and plugin-owned request handling decisions.

### Protocol support matrix

- HTTP/1.1 egress: supported.
- HTTPS (CONNECT + MITM): supported.
- HTTP/2 upstream over TLS (ALPN): supported by client path.
- h2c (prior knowledge): experimental feature (`experimental-h2c`) and not enabled by default.
- WebSockets: planned explicit bridge path (handshake hooks + bidirectional frame relay).

## Implementation Phases

### Phase 1: Explicit policy/forwarding boundaries (done)

- Introduce centralized outbound policy module used by all egress dial paths.
- Keep existing behavior but route allow decisions through one policy object.

### Phase 2: Internal layering refactor

- Split server responsibilities into explicit layers:
  - ingress handling (`CONNECT`, plain HTTP)
  - plugin pipeline (header/body/trailer hooks)
  - egress forwarding (HTTP client dial/send)
  - policy checks

### Phase 3: Unify forwarding path

- Keep `CONNECT` only as ingress mechanism.
- For intercepted HTTPS and plain HTTP, converge to one L7 forward pipeline.
- Minimize ad-hoc passthrough code to only non-intercepted tunnel use-cases.

### L4 passthrough behavior

- Non-HTTP protocols are supported through CONNECT-based L4 tunneling.
- L4 passthrough remains policy-gated by outbound allow rules and seccomp
  proxy-only egress enforcement when `network.egress = "proxy-only"`.

### Phase 4: WebSocket explicit path

- Add dedicated bridge path for WS upgrades.
- Keep header hooks on handshake request/response.
- Defer frame-level Wasm interception to a later phase unless required.

### Phase 5: HTTP/2 stabilization

- Stabilize TLS HTTP/2 egress path with trailer coverage.
- Keep h2c behind experimental guard until protocol correctness is proven.

### Phase 6: AWS SigV4-ready mode

- Add signing-safe mode:
  - force body buffering for signed requests,
  - deterministic canonicalization point,
  - no post-signing mutation drift.

## Testing Strategy

Required invariants for every forwarding change:

- Disallowed domains are blocked in both proxy and seccomp paths.
- Allowed domains pass.
- Header injection/removal stays correct.
- Streaming and buffered body callbacks preserve EOS semantics.
- Trailer mutation remains functional.

Protocol-specific tests:

- HTTP/1.1 passthrough/intercept.
- HTTPS CONNECT+MITM intercept.
- Response trailer mutation.
- WebSocket bridge tests (once implemented).
