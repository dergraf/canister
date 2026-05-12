# Canister WebAssembly ABI (ExtProc Style)

Canister provides an Envoy ExtProc-inspired WebAssembly ABI to intercept and modify HTTP/HTTPS traffic at different stages of the request/response lifecycle.

## Overview

A Wasm plugin built for Canister can export the following functions (callbacks):

- `on_request_headers`: Called when request headers are received.
- `on_request_body`: Called when a request body chunk is received (can be streamed).
- `on_response_headers`: Called when upstream response headers are received.
- `on_response_body`: Called when a response body chunk is received.

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

### Action (Response from Plugin)

Plugins must return a JSON response indicating the action to take:

```json
{
  "action": "Continue",
  "mutations": {
    "set_headers": { "X-Custom-Header": "Value" },
    "remove_headers": ["User-Agent"]
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
