# Conformance checklist - spec v0.2

Run this against your own server. Report results (including failures - especially failures) to joakim@jardenberg.com.

1. [ ] Envelope lives in `_meta["org.jardenberg.verifiable-mcp"]` with `spec`, `alg`, `kid`, `signed: "wrapper"`, `jws` - and nothing security-bearing outside the JWS
2. [ ] Signed wrapper contains `iat`, `payload`, `payload_digest`, `content_digest`, `provenance`
3. [ ] Canonicalization is RFC 8785 via a tested library
4. [ ] `content_digest` = SHA-256 over the exact bytes of the served text arm (binding by digest; text stays human-readable)
5. [ ] Key discoverable from your MCP server card (`signing` block with standard `jwks`); `kid` is the RFC 7638 thumbprint
6. [ ] Provenance carries exactly ONE rights field: `license` (you own it) / `legal_basis` (you index it) / `rights` (per-item/author)
7. [ ] Any AI-authored material inside the payload carries an explicit label, inside the signed scope
8. [ ] Error responses are signed (`payload = {id, error{code, message}}`)
9. [ ] Missing key degrades to unsigned - never to downtime
10. [ ] `verify.py --vectors` and `verify.mjs --vectors` pass against the published test vectors; `--live` passes against your endpoint
