# Verifiable MCP responses - pattern spec v0.2

*Working pilot of C2PA-spirit provenance for MCP tool output. Signed, sourced, reproducible. Three reference implementations run v0.1 in production and are migrating to v0.2: [ensakidag.se](https://ensakidag.se/mcp), [rise-ai-sweden.jardenberg.org](https://rise-ai-sweden.jardenberg.org), [sswcboken.se](https://sswcboken.se/mcp).*

**Changes from v0.1**, driven by two rounds of external multi-model review: the signed object is now a wrapper (fixes both the `content`/`structuredContent` divergence hole and the fact that `structuredContent` may be any JSON value), all digests moved *inside* the signed wrapper, content binding works by digest so the text arm stays human-readable, the envelope moved into namespaced `_meta`, canonicalization is RFC 8785 normatively, responses carry `iat`, errors are signed, and conformance requires published test vectors. **Removed from v0.1, explicitly:** `content_hash` and `content_hash_scope` are superseded by `payload_digest` inside the signed wrapper - v0.1 adopters must migrate those fields, they do not silently coexist. The v0.1 per-method scope labels (`structuredContent` / `result.contents`) are superseded by one signed scope, the wrapper, applied to **both** `tools/call` and `resources/read` (for resources, `payload` is the `contents` object).

## 1. What is signed

The server signs a **wrapper object**, never the raw tool output:

```json
{
  "iat": 1787308800,
  "payload": <the tool's actual result data - any JSON value>,
  "payload_digest": "sha256:<hex over the RFC 8785 canonical payload>",
  "content_digest": "sha256:<hex over the exact bytes of the text arm>",
  "provenance": { ... }
}
```

This applies to `tools/call` (payload = the result data) and `resources/read` (payload = the `contents` object) alike. The wrapper closes two holes at once: `structuredContent` may be any JSON value in current MCP, so there is always an object to sign and a place for provenance; and both digests live **inside the signature**, so nothing security-bearing sits where an attacker can rewrite it.

The signature attests exactly one thing: this wrapper left this server unaltered, minted at `iat`. It does not attest truth - only origin, integrity, and declared provenance.

## 2. Envelope

The envelope lives in the response's **`_meta`** under a reverse-DNS key (second label `jardenberg`, so outside MCP's reserved prefixes):

```json
"result": {
  "resultType": "complete",
  "content": [ { "type": "text", "text": "<human-readable rendering>" } ],
  "structuredContent": <payload>,
  "_meta": {
    "org.jardenberg.verifiable-mcp": {
      "spec": "0.2",
      "alg": "EdDSA",
      "kid": "<RFC 7638 JWK thumbprint>",
      "signed": "wrapper",
      "jws": "<compact JWS over the RFC 8785 canonical wrapper>"
    }
  }
}
```

Rules: anything outside the JWS is **convenience-only, never security-bearing** - a verifier trusts only what it recovers from the verified JWS payload. Servers MAY mirror `iat` or digests into the envelope for debugging; if a mirrored value and the signed value disagree, **the signed value wins** and the response should be treated as suspect. During migration, servers dual-emit the v0.1 sibling `signature` object; it is deprecated and disappears in v0.3.

Status honestly stated: this is **unnegotiated `_meta` today** - legal under MCP's namespacing rules, invisible to clients that ignore it. The v1.0 ambition is a negotiated extension (reverse-DNS ID declared via capabilities, per the 2026-07-28 extensions framework, whose Extensions Track requires a reference implementation in an official SDK - that is the real standardization roadmap item).

## 3. Canonicalization: RFC 8785, normatively

The JWS payload is the **RFC 8785 (JCS)** canonicalization of the wrapper - the RFC, including ECMAScript number serialization, I-JSON conformance, and hard errors on lone surrogates. Implementations use a tested JCS library, not hand-rolled sorting. (v0.1's sorted-keys rule produces identical bytes for the string-and-integer JSON these corpora emit, which is exactly why the upgrade is cheap now and expensive after someone's floating-point timestamp diverges later.)

## 4. Key discovery

- Discovery entry point: the server's MCP server card, carrying a `signing` block: `alg`, current `kid`, `previous_kids`, a standard **`jwks`** key set, the canonicalization statement, and `spec: "org.jardenberg.verifiable-mcp/0.2"`.
- **Path caveat, honestly:** the server-card location is not yet frozen upstream - `/.well-known/mcp.json` originates in SEP-1649 (an experimental extension), and an open issue proposes `/.well-known/mcp/server-card`. Servers SHOULD serve the card at `/.well-known/mcp.json` **and** follow the standardized path when one lands; verifiers should try both. A dedicated key file MAY additionally exist for convenience.
- `kid` is the RFC 7638 JWK thumbprint. Rotation: publish the new key alongside the old in the JWKS, switch signing, retire the old key when its signatures no longer matter. No revocation protocol in v0.2 - see §9.
- Optional external anchoring (recommended): publish key fingerprints somewhere the origin operator cannot silently rewrite - a signed git tag, DNS TXT, or a transparency log. This upgrades the trust root beyond same-origin DNS+TLS.

## 5. Provenance block

Inside the signed wrapper. Required: `server_operator`, `canonical_origin`/`canonical_url`, `dataset_version`, `last_updated` (derived from data, never hardcoded), and **exactly one rights field**:

1. `license` - only when the operator owns the content and grants a license (ensakidag: `CC-BY-4.0`).
2. `legal_basis` - when indexing third-party content: the basis, and that copyright stays put (rise-ai-sweden: "EU TDM exception (DSM art. 3-4); all content remains © its publisher").
3. `rights` - per-item or per-author rights when no blanket grant exists (sswcboken: "per author; not Creative Commons").

Human-readable strings in v0.2; alignment with structured rights vocabularies (RSL, IETF AI-Pref) is v0.3 work, so the block composes with machine-readable licensing rather than staying bespoke.

**AI-content labeling:** any AI-authored or AI-derived material inside the payload carries an explicit inline label distinguishing it from human-authored source material (sswcboken: "AI-fantasi i författarens anda - INTE författarens egna ord"). The signature covers the label: the human/AI distinction itself is tamper-evident. This - not the cryptography - is the pattern's differentiator.

## 6. Content binding - by digest, not by identity

The `content` text arm is what humans see and what non-structured clients feed the model; it MUST stay human-readable. The binding therefore works by digest:

- The signed wrapper's `content_digest` is SHA-256 over the **exact bytes** of `content[0].text` as served.
- Servers are free to render the text arm as prose, markdown, or serialized JSON - whatever serves the reader - as long as it is derived from `payload` and its digest is signed.
- A verifier that consumes the text arm MUST hash the text it actually rendered and compare against the signed `content_digest`; a verifier that consumes `structuredContent` compares its canonicalization against the signed `payload_digest` (or simply against `payload` inside the verified wrapper).
- Nothing outside the JWS may be used for any of these checks. A signature over a field nobody reads protects nobody - and an unsigned digest protects even less.

## 7. Freshness

The wrapper carries `iat` (Unix seconds); servers MAY add `exp`. **Stated replay scope:** for public archive corpora, `iat` is a freshness signal, not an anti-replay mechanism - a captured response replayed later still verifies, and now visibly carries the time it was minted, which is the honest claim. Deployments where replay is a real attack (transactions, credentials, paywalled or per-user data) need request binding - an optional `req` field (client nonce echoed inside the wrapper), out of scope for the reference corpora, in scope for the spec.

## 8. Errors

JSON-RPC error responses carry the same `_meta` envelope when the signing key is available. The signed wrapper's `payload` for an error is the object `{ "id": <request id>, "error": { "code": ..., "message": ..., "data": ... } }` - code, message, and request binding included, so "tool unavailable" is not a free lie. Where an SDK path cannot attach `_meta` to errors, the server documents that gap rather than silently skipping it.

## 9. Degradation and limits (read before citing this pattern)

- No key → serve **unsigned rather than not at all**. Signing never takes a corpus offline; an unsigned response from a normally-signing server is a visible anomaly.
- A signature proves origin and integrity, **never truth**. The ladder: (1) server authenticity, (2) payload integrity, (3) declared provenance - delivered. It *enables* (4) source authority and (5) answer fidelity. It never touches (6) truth. And per corpus: operator-equals-author (ensakidag) approaches "this person's archive said this"; a third-party index (rise-ai-sweden) proves *the index served this representation* - not that the upstream publisher wrote those words.
- The trust root is the origin (DNS+TLS) plus optional external anchoring (§4). No revocation, no timestamping authority, no transparency requirement. Documented, not hidden.
- **Caching interaction:** the 2026-07-28 protocol's `ttlMs`/`cacheScope` hints mean a `public`-scoped signed response can be cached by a shared gateway and served to a different user - verifying perfectly. Harmless for public archives; anyone copying this pattern onto authenticated or per-user data must scope caches accordingly or use request binding (§7).
- No MCP client verifies automatically yet; gateways and audit pipelines are the near-term verifiers.
- Adjacent work, named: Web Bot Auth / RFC 9421 sign the *caller and the pipe*; AP2 signs *payment mandates*; SEP-1766 pins *tool versions*; an open MCP discussion proposes C2PA credentials via `_meta`; a Server Attestation Document proposal uses `/.well-known/mcp-attestation`; the peer-reviewed Trustworthy MCP Registry work (MDPI, Future Internet 18:243) independently composes RFC 8615 discovery + JCS/JWS integrity + Sigstore transparency; and Sirenic ships a commercial MCP server pitched on "verify the signature, then read the provenance". This pattern signs the *content payload* of a knowledge corpus with rights and honesty labels inside the envelope - complementary to all of the above; the independent convergence is the point.

## 10. Conformance

A server conforms to v0.2 when: envelope in namespaced `_meta` as §2 · RFC 8785 via a tested library · wrapper with `iat`, `payload`, `payload_digest`, `content_digest`, `provenance` · digest-based content binding enforced · key discovery per §4 with thumbprint kid · exactly one rights field · AI content labeled inside the signed scope · errors signed as §8 · unsigned degradation · **published test vectors** - a known test JWK (private key included, clearly marked TEST), one sample payload, its RFC 8785 canonical bytes, both digests, and the expected JWS. The vectors exist in the reference repo **before** any public conformance claim; until a stranger can falsify your verifier against known answers, conformance is aspiration, not fact.

*Studio Jardenberg, August 2026. v0.2. Reference implementations migrating from v0.1 as of 2026-08-21. Feedback: the whole point.*
