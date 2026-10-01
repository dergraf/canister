# ADR-0020: The Session Entropy Budget Under Multi-Turn Agents

## Status
Accepted

## Date
2026-10-01

## Context

`[network.dlp] session_entropy_budget` (default 8192) limits how many high-entropy
bytes a sandbox may send. After a request body passes the pattern scan, the proxy
counts its 32-byte windows with Shannon entropy above 4.0 bits and adds them to a
running total. Once the total passes the budget, requests are refused with 451. The
heuristic targets slow exfiltration: an encrypted blob or a credential split across
many requests, none of which trips a detector on its own.

Two things about it were wrong.

**It is enforced per host, not per session.** Since F7 of the DLP plan the total is
kept per destination host (`PerHostEntropyBudget`), so one noisy upload cannot block
unrelated traffic and an attacker cannot spread a payload thinly across many hosts.
The configuration reference and `DLP.md` still described a single per-session
counter. The budget also cannot be set per host. It is one number for every
destination.

**It charges the same bytes again on every turn.** An agent's tool loop resends the
whole conversation on every request. A reasoning model's assistant turns each carry a
signed thinking block of about 1 KB of base64, which has to be sent back unchanged.
Turn *n* therefore re-sends *n − 1* blocks the provider already has, plus one new
one. The total grows with the square of the turn count. A real agent on a reasoning
model was refused with 451 on its third turn of an ordinary task. Any agent on any
reasoning model hits this.

The obvious workaround is to raise the budget globally, but that loosens the
heuristic for every host, including the ones it exists to protect.

## Options Considered

### Option 1: Raise the default budget
**Description**: Pick a default large enough for a long agent session.
**Pros**:
- No code.
**Cons**:
- Loosens the check for every destination, including arbitrary allowed hosts an
  attacker could use as a drop.
- Does not fix the quadratic growth, only moves the turn on which it bites. A long
  enough session always hits it.
**Estimated effort**: None

### Option 2: Per-host override on `[[host]]`
**Description**: `session_entropy_budget = N` on a `[[host]]` block replaces the
session default for that host.
**Pros**:
- It is explicit and audited, and it sits next to the host's other trust decisions
  (`allow_credentials`).
- Every other host keeps the default.
**Cons**:
- On its own it still charges the history again on every turn, so the override has
  to grow with the square of the session length. A budget big enough for a long
  session is big enough to carry a lot of new data too.
- Merging needs a rule, because recipe composition only adds.
**Estimated effort**: Low

### Option 3: Charge only bytes the destination has not been sent
**Description**: Remember what each host has already received. A window that host
was already sent in this session is not charged again.
**Pros**:
- Fixes resent history for every agent and every provider, with no special
  cases and no configuration.
- The budget then counts what it was meant to count: new high-entropy data
  reaching a destination.
**Cons**:
- Changes the default counting, so the change has to be argued to never let a new
  byte through uncharged.
- Costs memory per host, which needs a bound.
- On its own it leaves the linear term. A reasoning model's new signatures alone
  are about 1.4 KB per turn, which still exhausts 8 KiB within about six turns.
**Estimated effort**: Medium

### Option 4: Both (chosen)
**Description**: Option 3 by default, plus Option 2 for providers that legitimately
receive more new high-entropy data than the default allows.
**Pros**:
- Deduplication makes the budget linear in what is actually new, so a per-host
  number can be sized to a session's real traffic instead of its square.
- The override stays narrow: one host, one credential-trusted block.
**Cons**:
- Two mechanisms to explain instead of one.
**Estimated effort**: Medium

## Decision

**Option 4.**

### Deduplication: count each window once per destination

`PerHostEntropyBudget::charge` replaces the bare byte counter on the proxy's
request path:

1. Find the body's high-entropy windows with the same scan as before
   (`high_entropy_windows`; `high_entropy_byte_count` is now its sum, and a
   property test pins it to the old counter).
2. Hash each window together with a *scope* (below) under a per-session random
   SipHash key, and charge only the windows whose digest the host's record does
   not hold.
3. If the request is within budget, record the digest of **every 32-byte slice at
   every offset** of each run of adjacent hits that contained a new window. The
   scan aligns its windows relative to what precedes them, so a resent run can be
   cut at different offsets. Recording every offset makes any 32-byte slice of
   delivered data match, however it is aligned. A run made only of known windows
   is not re-recorded. Slices across the seam between two known windows then stay
   chargeable, which errs towards blocking.

The scope is the request's path and query plus the values of its credential
headers (`authorization`, `proxy-authorization`, `x-api-key`, `api-key`,
`x-goog-api-key`, `cookie`), as the sandbox sent them (before the fake-secret
swap). The record lives under the host.

**Why this lets no new data through.** Every distinct window is charged the first
time it reaches a given host under a given scope. What is skipped is a window that
same recipient already holds. Resending it adds nothing the recipient did not have.
An attacker who sends a secret once pays for it once, and repeating it is useless
as exfiltration: the bytes are already there. Under the old counting, repeating
also cost the attacker budget, but they had no reason to repeat. The budget's
power to stop an exfiltration was always the first charge, and that is unchanged.

Other properties keep it from being turned into a loophole:

- **The recipient is narrower than the host.** The same bytes sent to another
  host, path or credential are charged again. Without the scope, data delivered
  to the user's own private repository on a shared host could be re-posted to an
  attacker's gist on the same host for free. With it, another account or another
  endpoint is a new recipient. Within one endpoint and one credential the data
  stays in the same account. A rotated token or a cookie that changes per request
  only makes deduplication miss, which charges more, not less.
- **A refused body is not recorded.** It never reached the host, so retrying it
  is charged again. Under `--monitor` an over-budget body is forwarded but not
  recorded, so a resend is charged again there as well.
- **Repeats within one body are each charged**, as before. Only data from earlier
  requests is free.
- **Digests are keyed per session**, so a workload cannot construct a new window
  that collides with a recorded one.
- **Choosing which old windows to resend is a covert channel**, at roughly
  log2(recorded windows) bits per resent window. It is no stronger than the
  channel the budget never covered: low-entropy text is not charged at all, and
  choosing words from a dictionary carries the same few bits per token for free.
  The budget limits how many raw high-entropy bytes leave. It never bounded
  information encoded in what is sent, and this does not change that.
- **A body that charges nothing passes even on an exhausted budget.** That was
  already true of a body without high-entropy bytes. A fully resent body is now
  the same case.

**Memory.** Only bodies within budget are recorded, so a host's record grows with
the new high-entropy bytes it was charged for, which is bounded by its budget:
about 8 K digests at the default. A hard cap of 2^20 digests per host (about
20 MB at worst) bounds a host given a large override. Past the cap nothing more is
recorded and resent bytes are charged again. That fails towards blocking, never
towards letting bytes through. Hashing happens outside the table lock.

### Per-host override

```toml
[[host]]
domain                 = "api.anthropic.com"
allow_credentials      = ["anthropic_key"]
session_entropy_budget = 1048576
```

- **Credential scope required.** The override is for a destination the policy
  already trusts with a credential. A block that sets it without a non-empty
  `allow_credentials` is rejected when a recipe or manifest is parsed. The proxy
  also ignores the override on such a block (`HostBlock::entropy_budget_override`),
  in case a block was built without parsing. It has to be in the *same* block, so
  the trust decision can be audited in one place, and the merged block always
  keeps it, because `allow_credentials` merges by union.
- **Dropped with credential scope.** ADR-0008's rule strips `allow_credentials`
  from a recipe that does not match a pinned checksum. The override is stripped
  with it, so an untrusted recipe cannot raise a budget.
- **Merges by min.** When two recipes set it for the same domain, the smaller
  value wins. A later recipe can tighten a shipped provider's budget but cannot
  raise it. This is deliberately the opposite of `max_request_bytes` (max wins):
  that cap governs shape, while this one governs how much a host can be sent, and
  the point of the field is that loosening it is a reviewed decision. A recipe
  can still *introduce* an override where none was set. That is the loosening the
  field exists for, and it is gated by the credential rules above. The global
  `[network.dlp] session_entropy_budget` keeps its last-Some-wins merge. Changing
  it is out of scope.
- **Resolution** uses the contract table's most-specific `[[host]]` match, like
  `contract_mode`. If the most specific block sets no override, the session default
  applies, even if a broader wildcard block sets one.
- **Unset is not serialized**, so a policy that does not use the field keeps its
  `policy_resolved` hash (ADR-0014).

### Documentation

`DLP.md` and `CONFIGURATION.md` now say what is enforced: a budget per destination
host per session, which bytes are charged, the per-host override, and that bodies
above `max_buffered_body_bytes` (streamed, not buffered) are not charged.

## Consequences

### Positive
- An agent on a reasoning model is charged for what each turn adds, not for its
  whole history again. With deduplication, the 20-turn simulation in the tests
  charges about 27 KB. Counting the history every turn charges several hundred KB.
- A provider can get a budget sized for real sessions without loosening any other
  destination.
- The documentation matches the enforcement.

### Negative
- The default counting changed. The argument above is that it only removes
  double counting. The tests show that new high-entropy data still exhausts the
  budget at exactly the old boundary, and that resending to another host, scope,
  or after a refusal is charged again.
- Deduplication alone does not admit a long reasoning session under the 8 KiB
  default: the new signatures exhaust it within about six turns. Such a run
  still needs an override on its provider's block. Mitigated by the 451's
  `entropy-budget` detector header and the documentation pointing at the field.
- Each host keeps a digest set, bounded by its budget and a hard cap.

### Neutral
- `DlpScanner::check_entropy_budget` takes an `EntropyDestination` (host, scope,
  override) instead of a bare host.
- The field is not yet in the landing page's recipe catalog or form.

## Follow-up Actions
- [ ] Decide whether the shipped provider recipes (`service:anthropic`,
      `service:openai`) should set a `session_entropy_budget`. Doing so would loosen
      the default for every user of those recipes, so it was left out of this
      change.
- [ ] Charge streamed bodies (above `max_buffered_body_bytes`) to the budget.
- [ ] Surface `session_entropy_budget` in `can-docgen`'s recipe catalog and the
      landing-page host form.
