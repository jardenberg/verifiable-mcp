#!/usr/bin/env python3
"""verifiable-mcp one-command verifier (spec v0.2.1).

Offline:  python3 verify.py --vectors ../test-vectors/v0.2.1.json
Live:     python3 verify.py --live https://ensakidag.se/api/mcp [tool] [json-args]

Needs: pip install cryptography          (required)
       pip install rfc8785               (recommended - real JCS; fallback is
                                          sorted-keys compact JSON, byte-identical
                                          for string/int data)

Verifier hygiene, per spec S10: alg pinned to EdDSA; typ must be
"verifiable-mcp+jws"; kid resolved against the discovered JWKS, FAIL CLOSED on
a miss; jwk/jku/x5u headers ignored; nothing outside the JWS is trusted.
"""
import sys, json, base64, hashlib, urllib.request

SPEC_KEY = "org.jardenberg/verifiable-mcp"
REQUIRED_TYP = "verifiable-mcp+jws"

def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def canonicalize(value) -> bytes:
    try:
        import rfc8785  # type: ignore
        return rfc8785.dumps(value)
    except ImportError:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

class VerifyError(Exception):
    pass

def verify_jws_strict(jws: str, jwks: list) -> tuple:
    """RFC 8725-style strict verify. Returns (header, payload_bytes)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    h, p, s = jws.split(".")
    header = json.loads(b64u_decode(h))
    if header.get("alg") != "EdDSA":
        raise VerifyError(f"alg pinning: expected EdDSA, got {header.get('alg')!r}")
    if header.get("typ") != REQUIRED_TYP:
        raise VerifyError(f"typ: expected {REQUIRED_TYP!r}, got {header.get('typ')!r}")
    for banned in ("jwk", "jku", "x5u", "x5c"):
        if banned in header:
            raise VerifyError(f"key-carrying header {banned!r} present; ignored keys only come from discovery")
    jwk = next((k for k in jwks if k.get("kid") == header.get("kid")), None)
    if jwk is None:
        raise VerifyError(f"kid {header.get('kid')!r} not in discovered JWKS - failing closed")
    pub = Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
    pub.verify(b64u_decode(s), f"{h}.{p}".encode())  # raises InvalidSignature
    return header, b64u_decode(p)

def check_wrapper(wrapper: dict, payload_bytes: bytes, content_text, verbose: bool = False):
    def ok(label):
        if verbose: print(f"  [PASS] {label}")
    if payload_bytes != canonicalize(wrapper):
        raise VerifyError("JWS payload != canonical wrapper")
    ok("JWS verifies; payload == canonical wrapper (typ, alg, kid all strict)")
    if not isinstance(wrapper.get("iat"), int):
        raise VerifyError("iat missing from signed wrapper")
    for banned in ("content_hash", "content_hash_alg", "content_hash_scope"):
        if banned in wrapper.get("provenance", {}):
            raise VerifyError(f"v0.1 field {banned!r} inside signed wrapper (banned in v0.2.1)")
    pd = "sha256:" + sha256_hex(canonicalize(wrapper["payload"]))
    if pd != wrapper.get("payload_digest"):
        raise VerifyError("payload_digest does not reproduce")
    ok("payload_digest reproduces (inside signed wrapper)")
    if content_text is not None:
        cd = "sha256:" + sha256_hex(content_text.encode("utf-8"))
        if cd != wrapper.get("content_digest"):
            raise VerifyError("content_digest does not match the served text arm")
        ok("content_digest matches the served text arm bytes")
    prov = wrapper.get("provenance", {})
    rights = [k for k in ("license", "legal_basis", "rights") if k in prov]
    if "error" not in wrapper.get("payload", {}) and len(rights) != 1:
        raise VerifyError(f"provenance must carry exactly one rights field, found {rights}")
    ok("iat present; no v0.1 content_hash* fields; exactly one rights field")

def run_case(wrapper, jws, jwks, content_text):
    header, payload_bytes = verify_jws_strict(jws, jwks)
    check_wrapper(wrapper, payload_bytes, content_text)

def run_vectors(path: str):
    v = json.load(open(path))
    if "spec_version" not in v or "cases" not in v:
        print("This is a v0.2-format vector file (single case, superseded).")
        print("Use test-vectors/v0.2.1.json - the current set with negatives.")
        sys.exit(2)
    print(f"verifiable-mcp vectors: {v['spec']} v{v['spec_version']} - {len(v['cases'])} cases")
    jwks = v["jwks"]["keys"]
    failures = 0
    for c in v["cases"]:
        try:
            run_case(c["wrapper"], c["jws"], jwks, c.get("content_text"))
            outcome = "pass"
            detail = ""
        except Exception as e:
            outcome = "fail"
            detail = str(e)
        ok = outcome == c["expect"]
        print(f"  [{'PASS' if ok else 'UNEXPECTED'}] {c['name']}: verified={outcome=='pass'}"
              + (f"  ({detail})" if detail and ok else "")
              + ("" if ok else f"  EXPECTED {c['expect']!r}"))
        if not ok:
            failures += 1
    if failures:
        print(f"{failures} case(s) behaved unexpectedly"); sys.exit(1)
    print("ALL CASES BEHAVED AS EXPECTED (positives verify, negatives rejected)")

def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "verifiable-mcp-verifier/0.2.1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

def run_live(endpoint: str, tool: str = None, args_json: str = "{}"):
    origin = endpoint.split("/api/")[0]
    tool = tool or "server_info"
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": json.loads(args_json)}}).encode()
    req = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Method": "tools/call", "Mcp-Name": tool,
        "User-Agent": "verifiable-mcp-verifier/0.2.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read().decode()
    if raw.lstrip().startswith("data:") or "\ndata:" in raw:
        line = next(l for l in raw.splitlines() if l.startswith("data: "))
        msg = json.loads(line[6:])
    else:
        msg = json.loads(raw)
    result = msg.get("result") or {}
    env = ((result.get("_meta") or {}).get(SPEC_KEY)
           or ((msg.get("error") or {}).get("data") or {}).get(SPEC_KEY))
    if not env:
        if result.get("signature"):
            print("v0.1 envelope detected (sibling `signature`, no namespaced _meta).")
            print("Migration in progress - re-run after the server moves to v0.2.1.")
            sys.exit(2)
        print("No signature envelope found - this server does not sign (or serves unsigned degradation).")
        sys.exit(2)
    print(f"v0.2 envelope found (spec {env.get('spec')}, kid {str(env.get('kid'))[:12]}...)")
    card = fetch_json(origin + "/.well-known/mcp.json")
    jwks = ((card.get("signing") or {}).get("jwks") or card.get("jwks") or {}).get("keys", [])
    if not jwks:
        print("No JWKS discoverable from the server card - failing closed."); sys.exit(2)
    header, payload_bytes = verify_jws_strict(env["jws"], jwks)
    wrapper = json.loads(payload_bytes)
    print("Verifying against live wire:")
    text = None
    content = result.get("content") or []
    if content and content[0].get("type") == "text":
        text = content[0]["text"]
    check_wrapper(wrapper, payload_bytes, text, verbose=True)
    if result.get("structuredContent") is not None and not result.get("isError"):
        if canonicalize(wrapper["payload"]) != canonicalize(result["structuredContent"]):
            raise VerifyError("signed payload != served structuredContent")
        print("  [PASS] signed payload == served structuredContent")
    elif result.get("isError"):
        print("  [INFO] isError result - signed via the error-wrapper path, no structuredContent expected")
    print("ALL CHECKS PASSED (live)")

if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        if len(a) >= 2 and a[0] == "--vectors":
            run_vectors(a[1])
        elif len(a) >= 2 and a[0] == "--live":
            run_live(a[1], a[2] if len(a) > 2 else None, a[3] if len(a) > 3 else "{}")
        else:
            print(__doc__); sys.exit(1)
    except VerifyError as e:
        print(f"  [FAIL] {e}"); sys.exit(1)
