# Why was my request refused?

The proxy can refuse a request for two distinct reasons. Both are
visible in the response status code and the `x-canister-error`
response header — log scrapers should pivot on the header, humans
read the body.

| Class                | Status                | `x-canister-error`        | Cause                                              |
| -------------------- | --------------------- | ------------------------- | -------------------------------------------------- |
| Connect refusal      | `502 Bad Gateway`     | `policy-blocked`          | Host wasn't reachable at all (no `[[host]]`, IP outside `reachable_ips`) |
| Contract refusal     | `415` or `413`        | `contract-refused`        | Host *is* reachable but the request *shape* isn't allowed |
| DLP detection        | `451 …Legal Reasons`  | `dlp-blocked`             | A credential / canary fired the regex             |
| Upstream timeout     | `504 Gateway Timeout` | `upstream-timeout`        | Upstream didn't respond in time                   |
| Body too large       | `413 Payload Too Large` | `body-too-large`        | Body exceeded the streamed-body cap                |

The two you'll see most often once a sandbox is running are
**contract refusals** and **DLP detections**. They look superficially
similar (both refuse a request the worker tried to send) but mean
different things, so it's worth being clear about which is which.

## Contract refusal (415 / 413)

> "The destination is reachable but this isn't a shape it accepts."

The contract gate runs *before* the DLP scanner. It checks four
things, in this order:

1. Is there a `[[host]]` block matching the destination FQDN? (Under
   `Strict` mode — the default. Under `Relaxed`, unknown hosts pass.)
2. Is the request method in `methods`?
3. Is the `Content-Type` in `content_types`?
4. Is the request path covered by `paths`?
5. Is the body size within `max_request_bytes`?

The first failing check produces the refusal. Each refusal response
includes the **exact `[[host]]` patch** you can paste into your
project's `canister.toml` to unblock yourself — no need to read
docs. For example:

```
HTTP/1.1 415 Unsupported Media Type
x-canister-error: contract-refused

Refused by canister: api.github.com does not accept Content-Type
`image/png`. Allowed: application/json, application/vnd.github+json.

To allow this for the current project, append to ./canister.toml:

    [[host]]
    domain = "api.github.com"
    content_types = ["image/png"]   # extends the shipped contract
```

Why the contract gate exists: the DLP scanner is a string-detection
problem with infinite encoding space — any sufficiently determined
attacker can wrap a credential in `base64(gzip(strip_seps(token)))`
and find a decoder we don't apply. The contract gate is the
asymmetric defence: a worker that *legitimately* needs to talk to
GitHub never POSTs a PNG to `api.github.com`. Closing the shape
gap is much cheaper than enumerating the encoding fringe.

See `docs/adr/0007-per-destination-egress-contracts.md` for the
full design.

## DLP detection (451)

> "The destination is reachable, the shape is fine, but the bytes
> look like a credential we know about."

This is the regex layer: ~14 credential types (GitHub PAT, AWS
access keys, OpenAI keys, Anthropic keys, npm tokens, SSH private
keys, …) plus session canaries. The scanner walks every header,
URI segment, JSON path, form value, multipart part, XML node, and
trailer, with an encoding-chain decoder (base64 / hex / percent /
gzip / zlib / zstd / ascii85 / utf16-le / xor) and a normalize
pass (strip separators, unicode-normalize, unescape).

A DLP block sets `x-canister-error: dlp-blocked` and includes
`x-canister-dlp-detector: <id>` naming which detector fired. The
log record (`event: dlp_block`) carries the redacted match text
and the source attribution (`source: header:X-Api-Key`,
`source: json:user.tokens[0]`, etc.).

Per-host scope policy: a `github_pat` finding on `*.github.com` is
downgraded from `Block` to `Warn` because that's where the token
legitimately belongs. To extend the legitimate-destinations list,
add the host to the `allow_credentials` field of the relevant
`[[host]]` block. For example, an enterprise mirror:

```toml
[[host]]
domain            = "github.corp.example.com"
methods           = ["GET", "POST", "PATCH", "PUT", "DELETE"]
content_types     = ["application/json"]
allow_credentials = ["github_pat"]   # treat as a github_pat home
```

### Fake secrets and the swap

When a recipe declares `[network.dlp] fake_secrets` for an env-var
secret (e.g. `GITHUB_TOKEN`), the sandbox only ever holds a **fake**
value. What you observe at the proxy depends on the destination:

- **Authorised host** (the credential's home domain or an
  `allow_credentials` entry): the request goes through. The proxy
  transparently swaps the fake for the real value before forwarding —
  the sandboxed tool works as if it had the real token.
- **Unauthorised host**: the fake matches its detector's regex and is
  refused with `451 dlp-blocked`, the same as a real credential would
  be. The real value never leaves the proxy.

So a `451 dlp-blocked` naming a faked credential means the sandbox tried
to send its (fake) token somewhere it isn't authorised. The fix is the
same as above — add the host to `allow_credentials` if the credential
legitimately belongs there. See [DLP](DLP.md#fake-secret-swap).

## I just want to debug something quickly

```bash
# One-off escape hatch — does not survive the next invocation.
can run --allow "api.github.com:image/png" -- my-script.sh
```

Or for prototyping where you don't know the upstream set up front,
flip the global mode to `Relaxed` in your `canister.toml`:

```toml
[network]
contract_mode = "relaxed"
```

`Relaxed` allows unknown hosts but still emits an
`unknown_host_contract` tracing event per request, so you can
read the event log and harvest the FQDNs into `[[host]]` blocks
once you know what your tool actually needs.

## Reading the logs

Every refusal also emits a structured event with the same reason
code:

```json
{"event":"dlp_block","host":"api.github.com","detector":"contract","matched_redacted":"content-type-not-allowed"}
```

For dashboards: `detector="contract"` is the contract gate;
`detector` matching a credential name is the DLP layer.

## TL;DR

- 415 / 413 with `x-canister-error: contract-refused` → wrong *shape* of request. Patch is in the body.
- 451 with `x-canister-error: dlp-blocked` → wrong *content* of request. Extend `allow_credentials` on the relevant `[[host]]` block if the credential legitimately belongs there.
- 502 with `x-canister-error: policy-blocked` → can't reach the destination at all. Add a `[[host]]` block.
