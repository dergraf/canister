# ADR-0021: `can keygen` and `can pubkey`

## Status
Accepted

## Date
2026-10-01

## Context

ADR-0016 lets `can` seal each event stream with an Ed25519 key named by
`--events-sign-key`: a file holding the 32-byte seed as raw bytes or 64 hex
characters. A seal is only worth something to a consumer that knows which public key
to trust, and `can` gave operators no way to produce either half:

- The seed had to come from somewhere else, in practice `openssl rand -hex 32`. That
  works, but it leaves file permissions to the operator, and a key written with the
  default umask is readable by every account on the machine.
- The public key — the one value a consumer needs — could only be learned by running a
  signed stream and copying `public_key` out of its `stream_seal`. A trust list built
  that way trusts whatever key the first run happened to use, which is the decision the
  trust list exists to make in advance.

## Options Considered

### Option 1: Document an `openssl` recipe
**Description**: Generate with `openssl rand -hex 32`, derive the public key with
`openssl pkey`.
**Pros**:
- No code.
**Cons**:
- `openssl pkey` wants a PKCS#8 or PEM key, not a bare seed; the conversion is an
  ASN.1 prefix spliced on by hand, which is not something a security procedure should
  rest on.
- The output is base64 or DER, not the hex a seal carries, so it needs a second
  conversion before it can be compared with anything.
**Estimated effort**: Low

### Option 2: `can keygen` and `can pubkey` (chosen)
**Description**: Two top-level subcommands. `keygen <path>` writes a new seed and
prints its public key; `pubkey <path>` prints the public key of an existing seed.
**Pros**:
- The public key is derived by the same code that signs, and printed in the form the
  seal carries, so there is nothing to convert and nothing to get wrong.
- The key file is created with mode 0600 from the start, not chmod-ed afterwards.
- `pubkey` reads every file `--events-sign-key` reads, so keys generated with
  `openssl` keep working and can be inspected the same way.
**Cons**:
- Two more subcommands in `can --help`.
**Estimated effort**: Low

### Option 3: A `can key` subcommand group
**Description**: `can key generate`, `can key public`.
**Pros**:
- Room for later key operations under one name.
**Cons**:
- There are no later key operations in view; a group with two members is ceremony.
**Estimated effort**: Low

## Decision

**Option 2.**

- `can keygen <path> [--force]` reads 32 bytes from `/dev/urandom`, writes them to
  `<path>` as 64 lowercase hex characters and a newline (what `openssl rand -hex 32`
  writes), and prints the public key on stdout.
- The file is created with `O_CREAT|O_EXCL` and mode 0600. An existing file is refused:
  replacing a key silently orphans every seal it signed. `--force` removes the old file
  and creates a new one rather than truncating it, so the new key never inherits a lax
  mode from the old file.
- **The seed is never printed.** stdout ends up in terminal scrollback and CI logs, the
  two places a signing key escapes from most often; a command that prints secrets by
  default turns that into the normal path. An operator who needs the seed in a secret
  store reads the file, which is a deliberate act.
- `can pubkey <path>` loads the file with `SealKey::from_file` — 32 raw bytes or 64 hex
  characters — and prints the public key.
- Both print the public key as 64 lowercase hex characters and a newline: exactly the
  `public_key` field of a `stream_seal` (ADR-0016), so a consumer's trusted-key list
  holds the line verbatim and compares it with a string comparison.
- Randomness comes from `/dev/urandom` rather than a new dependency: `can` is Linux
  only, and reading 32 bytes from the kernel's CSPRNG is the whole of what is needed.

## Consequences

### Positive
- Provisioning a seal key is two commands, and the trusted public key is fixed before
  the first run instead of learned from it.
- Key files start out owner-only.

### Negative
- An operator who wants the seed on stdout — to pipe it into a secret store — has to
  read the file instead. Accepted for the reason above.

### Neutral
- Key custody is unchanged: `can` does not store, rotate or escrow keys. Rotation is
  `keygen --force` plus updating the consumer's trusted keys.

## Follow-up Actions
- [ ] Integration tests that launch a sandbox could sign with a `keygen` key and check
      the seal against `pubkey`, closing the loop end to end.
