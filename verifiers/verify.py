#!/usr/bin/env python3
"""verifiable-mcp one-command verifier (spec v0.2).

Offline:  python3 verify.py --vectors ../test-vectors/v0.2.json
Live:     python3 verify.py --live https://ensakidag.se/api/mcp [tool] [json-args]

Needs: pip install cryptography          (required)
       pip install rfc8785               (recommended - real JCS; falls back to
                                          sorted-keys compact JSON, which is
                                          byte-identical for string/int data)
"""
import sys, json, base64, hashlib, urllib.request

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

def verify_jws(jws: str, x_b64u: str):
    """Verify compact EdDSA JWS; return (header, payload_bytes)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    h, p, s = jws.split(".")
    pub = Ed25519PublicKey.from_public_bytes(b64u_decode(x_b64u))
    pub.verify(b64u_decode(s), f"{h}.{p}".encode())  # raises on failure
    return json.loads(b64u_decode(h)), b64u_decode(p)

def check(label: str, ok: bool, detail: str = ""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))
    if not ok:
        sys.exit(1)

def thumbprint(jwk: dict) -> str:
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                       sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canon).digest()).rstrip(b"=").decode()

def verify_wrapper(wrapper: dict, envelope: dict, jwk_x: str, content_text=None):
    header, payload_bytes = verify_jws(envelope["jws"], jwk_x)
    check("JWS signature verifies (EdDSA)", True)
    check("JWS payload == canonical wrapper", payload_bytes == canonicalize(wrapper))
    check("kid in JWS header matches envelope", header.get("kid") == envelope.get("kid"))
    pd = "sha256:" + sha256_hex(canonicalize(wrapper["payload"]))
    check("payload_digest reproduces (inside signed wrapper)", pd == wrapper["payload_digest"])
    if content_text is not None:
        cd = "sha256:" + sha256_hex(content_text.encode("utf-8"))
        check("content_digest matches rendered text arm", cd == wrapper["content_digest"])
    check("iat present in signed wrapper", isinstance(wrapper.get("iat"), int))
    check("provenance present with a rights field",
          any(k in wrapper.get("provenance", {}) for k in ("license", "legal_basis", "rights")))

def run_vectors(path: str):
    v = json.load(open(path))
    print(f"verifiable-mcp vectors: {v['spec']}")
    jwk = v["test_jwk_public"]
    check("kid is RFC 7638 thumbprint of test key", thumbprint(jwk) == jwk["kid"])
    check("canonical wrapper bytes match published hex",
          canonicalize(v["wrapper"]).hex() == v["canonical_wrapper_utf8_hex"])
    verify_wrapper(v["wrapper"], {"jws": v["jws_compact"], "kid": jwk["kid"]},
                   jwk["x"], content_text=v["content_text"])
    print("ALL CHECKS PASSED (offline vectors)")

def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "verifiable-mcp-verifier/0.2"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

def run_live(endpoint: str, tool: str = None, args_json: str = "{}"):
    origin = endpoint.split("/api/")[0]
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool or "server_info", "arguments": json.loads(args_json)}}).encode()
    req = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "verifiable-mcp-verifier/0.2"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read().decode()
    if raw.lstrip().startswith("data:") or "\ndata:" in raw:
        line = next(l for l in raw.splitlines() if l.startswith("data: "))
        msg = json.loads(line[6:])
    else:
        msg = json.loads(raw)
    result = msg.get("result") or {}
    env = (result.get("_meta") or {}).get("org.jardenberg.verifiable-mcp")
    if not env:
        if result.get("signature"):
            print("v0.1 envelope detected (sibling `signature`, no namespaced _meta).")
            print("Migration in progress - re-run after the server moves to v0.2.")
            sys.exit(2)
        print("No signature envelope found - this server does not sign (or serves unsigned degradation).")
        sys.exit(2)
    print(f"v0.2 envelope found (spec {env.get('spec')}, kid {env.get('kid', '')[:12]}...)")
    # key discovery: server card first, then known dedicated files
    jwk = None
    for path in ("/.well-known/mcp.json",):
        try:
            card = fetch_json(origin + path)
            keys = (card.get("signing", {}).get("jwks") or card.get("jwks") or {}).get("keys", [])
            jwk = next((k for k in keys if k.get("kid") == env["kid"]), keys[0] if keys else None)
            if jwk: break
        except Exception:
            continue
    if not jwk:
        print("Could not discover a JWK from the server card - check the server's key discovery.")
        sys.exit(2)
    header, payload_bytes = verify_jws(env["jws"], jwk["x"])
    wrapper = json.loads(payload_bytes)
    print("Verifying against live wire:")
    text = None
    content = result.get("content") or []
    if content and content[0].get("type") == "text":
        text = content[0]["text"]
    verify_wrapper(wrapper, env, jwk["x"], content_text=text)
    check("wrapper payload == served structuredContent",
          canonicalize(wrapper["payload"]) == canonicalize(result.get("structuredContent")))
    print("ALL CHECKS PASSED (live)")

if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) >= 2 and a[0] == "--vectors":
        run_vectors(a[1])
    elif len(a) >= 2 and a[0] == "--live":
        run_live(a[1], a[2] if len(a) > 2 else None, a[3] if len(a) > 3 else "{}")
    else:
        print(__doc__)
        sys.exit(1)
