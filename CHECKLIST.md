# Conformance checklist - spec v0.2.1

Run this against your own server. Report results (including failures - especially failures) to joakim@jardenberg.com.

1. [ ] Envelope lives in `_meta["org.jardenberg/verifiable-mcp"]` with `spec`, `alg`, `kid`, `signed: "wrapper"`, `jws` - nothing security-bearing outside the JWS; JWS header `typ: "verifiable-mcp+jws"`
2. [ ] Signed wrapper contains `iat`, `payload`, `payload_digest`, `content_digest`, `provenance` - and NO v0.1 `content_hash*` keys; served `structuredContent` is canonically byte-identical to the signed `payload`
3. [ ] Canonicalization is RFC 8785 via a tested library
4. [ ] `content_digest` = SHA-256 over the exact bytes of the served text arm (binding by digest; text stays human-readable)
5. [ ] Key discoverable from your MCP server card (`signing` block with standard `jwks`); `kid` is the RFC 7638 thumbprint
6. [ ] Provenance carries exactly ONE rights field: `license` (you own it) / `legal_basis` (you index it) / `rights` (per-item/author)
7. [ ] Any AI-authored material inside the payload carries an explicit label, inside the signed scope
8. [ ] Error frames signed at `error.data` (`payload = {id, error{code, message}}`); `isError` results signed as `{isError, message}`
9. [ ] Missing key degrades to unsigned - never to downtime
10. [ ] Both verifiers behave correctly on ALL published vectors including negatives; `--live` passes against your endpoint
