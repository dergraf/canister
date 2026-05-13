# Canister WebAssembly ABI (ExtProc Style)

Forwarding model note: Canister uses an L7 semantic forwarding model (HTTP server + HTTP client), not byte-transparent tunneling. See `docs/proxy-forwarding-plan.md` for protocol/compatibility details.

Wasm callbacks apply to HTTP interception flows. L4 CONNECT passthrough for non-HTTP protocols is not Wasm-intercepted by default.

Canister provides an Envoy ExtProc-inspired WebAssembly ABI to intercept and modify HTTP/HTTPS traffic at different stages of the request/response lifecycle.

## Overview

A Wasm plugin built for Canister can export the following functions (callbacks):

- `on_request_headers`: Called when request headers are received.
- `on_request_body`: Called when a request body chunk is received (can be streamed).
- `on_request_trailers`: Called when request trailers are received.
- `on_response_headers`: Called when upstream response headers are received.
- `on_response_body`: Called when a response body chunk is received.
- `on_response_trailers`: Called when response trailers are received.

If a function is not exported, Canister passes the data through without modification.

## Data Structures

Canister communicates with the Extism Wasm plugin using JSON payloads.

### Headers Payload

```json
{
  "method": "GET",
  "uri": "https://example.com/api",
  "headers": {
    "host": "example.com",
    "user-agent": "curl/7.68.0"
  }
}
```

### Body Payload

```json
{
  "body": "aGVsbG8=",
  "end_of_stream": false
}
```

The `body` field is base64 encoded bytes for the current streamed chunk.
`end_of_stream` indicates this chunk is the final body chunk before trailers or stream end.

### Trailers Payload

```json
{
  "trailers": {
    "grpc-status": "0"
  },
  "end_of_stream": true
}
```

### Action (Response from Plugin)

Plugins must return a JSON response indicating the action to take:

```json
{
  "action": "Continue",
  "buffer_body": false,
  "mutations": {
    "set_headers": { "X-Custom-Header": "Value" },
    "remove_headers": ["User-Agent"]
  }
}
```

For body hooks (`on_request_body`, `on_response_body`), plugins should return:

```json
{
  "action": "Continue",
  "body": "aGVsbG8="
}
```

If the body field is omitted or invalid, Canister passes the original chunk through.

Header hooks may request body buffering by setting `buffer_body: true`.
When buffering is enabled, Canister collects the full body and sends exactly one body callback with `end_of_stream: true`.

Signature-aware request handling should be implemented in Wasm plugin logic (for example, by returning `buffer_body: true` and applying plugin-side policy). Canister runtime does not embed cloud/vendor-specific signing behavior.

### Body Delivery Modes

- `buffer_body: false` (default): body hooks are called for streamed chunks. The final callback is marked `end_of_stream: true`.
- `buffer_body: true`: body is fully buffered and body hook is called once with `end_of_stream: true`.

### Transfer-Encoding vs Content-Length Behavior

Body framing is hop-by-hop. After mutation, Canister may change transfer encoding for correctness:

- In streaming mode, Canister removes `content-length` and allows transfer-framed streaming (`chunked` in HTTP/1.1, DATA frames in HTTP/2).
- In buffered mode without trailers, Canister sets `content-length` to the mutated payload size and removes `transfer-encoding`.
- In buffered mode with trailers, Canister forces chunked transfer in HTTP/1.1 so trailers can be preserved.

This means an incoming chunked request can become fixed-length upstream (or the inverse) depending on plugin behavior.

For trailer hooks (`on_request_trailers`, `on_response_trailers`), plugins should return:

```json
{
  "action": "Continue",
  "mutations": {
    "set_headers": { "x-trailer": "value" },
    "remove_headers": ["grpc-status-details-bin"]
  }
}
```

Or to short-circuit and block:

```json
{
  "action": "Respond",
  "status": 403,
  "headers": { "Content-Type": "application/json" },
  "body": "eyJtZXNzYWdlIjogIkFjY2VzcyBEZW5pZWQifQ==" // base64 encoded
}
```

`Respond` is supported for header hooks. For body hooks, `Respond` is currently ignored and the original chunk is forwarded.

## Current Test Coverage

- HTTP and HTTPS passthrough behavior.
- Header hook interception and mutation.
- Streaming multi-chunk request/response body mutation with end-of-stream signaling.
- Buffered request/response body delivery with single callback and `end_of_stream: true`.
- HTTP/1.1 framing behavior validation:
  - buffered mutated responses use `content-length`
  - streaming mutated responses use `transfer-encoding: chunked`
- Response trailer mutation via `on_response_trailers` in streaming transfer mode.
- Simple policy use-cases:
  - passthrough without plugin
  - request header injection
  - request header removal
- HTTP/2 (h2c prior-knowledge) upstream test scaffold exists (currently ignored): forwarding path currently hits a protocol error and needs dedicated h2c transport handling before enabling in CI.

## Runtime DNS/IP Allowlist Behavior

- Static domain allowlists are pre-resolved at sandbox startup.
- A shared, TTL-aware DNS cache is now used by the proxy dial path and seccomp notifier refresh path.
- On outbound deny decisions, notifier attempts refresh of allowed domains via cache/system DNS and updates a dynamic IP allowlist.
- This allows policy to adapt to domain IP churn over time while preserving domain-based restrictions.
