# DLP property-based testing

This doc is the orientation for anyone touching DLP detection or its
test harness. It is intentionally short — the source of truth is
`crates/can-dlp/tests/proptest_pipeline.rs`. Read this first to know
what the harness does and why; read the source when you need to
change it.

## What the harness covers

Two invariants, encoded as two `proptest!` blocks (request direction)
plus a third for the response direction:

| Property                                         | What it asserts                                                                                                          |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| `any_encoded_canary_is_detected`                 | For every `(canary × transform-chain × channel)` triple, the scanner fires the *right* detector on the resulting request. |
| `verdict_source_matches_channel`                 | The verdict's `source` field points back to the channel the canary was stashed in (header value, URI query key, JSON path, …). |
| `any_encoded_canary_reflected_in_response_is_detected` | A malicious upstream can't sneak the session canary back via response headers (`Set-Cookie`, `Location`, `X-Reflect`, …) or response body — the response-direction scan catches every encoding. |

The three together give us: *if* the scanner ever needs to make a
catch, it *will*, *and* the operator knows where the leak was.

## How a generated test case is built

```
arb_canary()         ──►  ("github_pat", b"ghp_AAAA…")    │ one of the registry's positive vectors
arb_chain(3)         ──►  Chain { inner: Some(Rot13),     │ 0..1 inner-only op (Reverse, Rot13,
                                  comp:  [Base64Std,      │ InterleaveSep), then 0..3 compositional
                                          Gzip,           │ ops (Base64Std/Url, Hex, Percent,
                                          Hex] }          │ Gzip, Zlib, Zstd)
arb_channel()        ──►  HeaderValue { name: "Cookie" }  │ where in the request to stash it

      apply_chain(canary, chain)
              │
              ▼
       encoded bytes
              │
       build_request(channel, encoded)
              │
              ▼
        (headers, uri, body, content-type)
              │
       scanner.scan_request(…)
              │
              ▼
          Vec<ScanVerdict>      ──► prop_assert!(detector fires)
```

The response-direction property swaps `arb_channel`/`build_request`
for their `arb_response_channel`/`build_response` siblings and calls
`scanner.scan_response(…)`.

## Generator discipline (why we don't generate everything)

The harness is opinionated about what it generates. Generators have
to model the scanner's design, not just enumerate the input space —
otherwise it becomes a noise machine that finds the same "known
design limit" every run.

Two constraints baked into the generator:

1. **Two-tier ops.** Transforms are split into `CompOp`
   (compositional — base64, hex, gzip, …) and `InnerOp` (flat — reverse,
   rot13, interleave). Compositional ops walk through the BFS in
   `decode_layers` and stack freely. Inner-only ops are applied flat
   in `scan_text` (Normalize / LastResort) — they only get a chance to
   fire when they sit at the *bottom* of the chain (applied first to
   the raw canary). The generator enforces this: at most one `InnerOp`,
   placed before the compositional stack.

2. **Skip rules** in `skip_if_unrepresentable` / `skip_response_unrepresentable`:
   - **Wire-format rejects.** Binary in a header value is rejected by
     real HTTP parsers; non-UTF-8 in a JSON string round-trips lossy
     and isn't a real attack. We `prop_assume!` skip these cases.
     URI path/query handle binary via percent-encoding and are kept.
   - **Ambiguous interleavings.** `InterleaveSep('-')` against
     `sk-ant-…` or `InterleaveSep('_')` against `ghp_…` is genuinely
     undecidable without a per-detector oracle: the scanner has no
     way to tell which `-` chars were "real prefix" vs which were
     "interleaved noise." Skip with a documented rationale.

Anything not skipped is a real attack scenario that *must* be caught.
A failing case is therefore a real regression, not a known
limitation, and must land a fix in the same PR — never `#[ignore]`.

## Running the harness

```bash
# CI default: 128 + 32 + 96 cases, ~5s release, ~45s debug.
cargo test -p can-dlp --test proptest_pipeline

# Deeper sweep before merging risky DLP changes.
PROPTEST_CASES=1024 cargo test -p can-dlp --test proptest_pipeline

# Replay a specific case from the regression file.
cargo test -p can-dlp --test proptest_pipeline any_encoded_canary_is_detected
```

## The regression file

`crates/can-dlp/tests/proptest_pipeline.proptest-regressions` is the
on-disk record of every shrunken counterexample we've seen. It is
**checked in**. Every CI run replays it before generating any novel
cases, so a once-fixed bug can never silently come back.

When proptest finds a new failure:

1. Look at the "minimal failing input" block in the test output —
   that's the shrunken counterexample.
2. Decide whether it's a real regression (fix the scanner) or a
   design limit (extend `skip_if_unrepresentable` with a *written
   rationale*).
3. Commit the regression file changes alongside the fix.

Order matters: regression file first, then the fix. That way the
commit history shows the failing case existed, was demonstrated, and
got resolved.

## Extending the harness

| Add a new …                | Where it goes                                            |
| -------------------------- | -------------------------------------------------------- |
| Compositional encoder      | `CompOp` enum + `apply_comp` + `arb_comp_op()`           |
| Inner-only / normalize op  | `InnerOp` enum + `apply_inner` + `arb_inner_op()`        |
| Request exfil channel      | `Channel` enum + `arb_channel()` + `build_request` arm + new arm in the `verdict_source_matches_channel` match |
| Response exfil channel     | `ResponseChannel` enum + `arb_response_channel()` + `build_response` arm |
| Detector / canary fixture  | Append to the `known_canaries()` slice                   |
| Known design-limit skip    | Extend `skip_if_unrepresentable` with a `// rationale:` comment |

**Currently-modelled exfil channels** (so you know what's already pinned):

- *Headers (request)*: `X-Custom`, `Authorization`, `Cookie`, `User-Agent`, `Referer`, `Origin`, `Forwarded`, `Cache-Control` — covers every header an attacker controls end-to-end, including the ones the old skip-list exempted.
- *URI*: path segments, query keys (`q`, `token`).
- *JSON body*: depth-0 and depth-2 nested string fields.
- *HTTP/1.1 chunked trailers*: `X-Sig`, `X-Checksum` — previously a complete bypass.
- *Form-urlencoded body*: value attributed to its key (`token`, `api_key`).
- *Multipart/form-data*: part body attributed to Content-Disposition `name=`.
- *XML*: text nodes inside elements, attribute values on elements.
- *Headers (response)*: `Set-Cookie`, `Location`, `X-Reflect`, `Server` — reflective exfil through upstream.
- *Body (response)*: raw `text/plain` and JSON-wrapped.

**What's deliberately NOT modelled** (and why):

- *Binary structured formats* (protobuf, msgpack, BSON, CBOR): no per-schema walker, so structured attribution is impossible. Detection still works via the `BodyRaw` fallback when the credential bytes appear unobfuscated inside the binary stream, which covers the common case where a leaked string is wrapped in a length-prefix.
- *WebSocket frames*: the proxy currently returns `501 Not Implemented` for `Upgrade: websocket`, so there's no in-tree path to test.
- *HTTP/2 specific framing* (CONTINUATION frames, HPACK indexed-header tricks): hyper exposes headers uniformly across HTTP/1 and HTTP/2, so the request-direction proptest's coverage applies to both.

Whenever you add a channel, the `verdict_source_matches_channel`
match expression needs a new arm — otherwise the proptest will
loudly tell you ("unexpected source for channel").

## Why not just hand-written tests?

We have lots of those too (`scanner::tests::*`, `extract::tests::*`,
`response_scan::tests::*`). They're cheap to read and pin specific
known-good combinations. The proptest harness pairs with them to
cover:

- **The combinatorial fringe.** 7 compositional ops × 6 inner ops × 13
  channels × N canaries = thousands of `(encoding, location)` pairs
  no human is going to enumerate by hand.
- **Source-attribution regressions.** Easy to break silently while
  refactoring the extractor; the `verdict_source_matches_channel`
  property hammers it from every angle.
- **Bidirectional symmetry.** Request- and response-side scanners
  should behave the same way on the same encoding. The harness uses
  the *same* transform / canary generators for both directions, so a
  drift between `scan_request` and `scan_response` shows up
  immediately.

Hand-written tests document specific design intent; proptest tests
guard the property the design tries to deliver. Both are required.
