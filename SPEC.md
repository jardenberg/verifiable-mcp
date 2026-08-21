# Verifiable MCP responses - pattern spec v0.2.1

*Working pilot of C2PA-spirit provenance for MCP tool output. Signed, sourced, reproducible. Three reference implementations run this in production: [ensakidag.se](https://ensakidag.se/mcp), [rise-ai-sweden.jardenberg.org](https://rise-ai-sweden.jardenberg.org), [sswcboken.se](https://sswcboken.se/mcp).*

**Changes in v0.2.1** (conformance release, driven by an external reviewer who ran the published verifier against the live wires - which is exactly what the pattern asks of its readers): the `_meta` key follows MCP's namespaced-key grammar (`org.jardenberg/verifiable-mcp` - reverse-DNS prefix, slash, name, cf `io.modelcontextprotocol/clientInfo`); JWS `typ` is mandated to one explicit value; the error envelope moves to `error.data` where strict SDKs preserve it; tool-level `isError` results get a defined shape; `canonical_origin` is a string; `content_digest` is byte-precise; verifiers get hard requirements; the vector set gains prose-arm, resources, error, and negative cases; and the v0.1 `content_hash*` fields are banned from inside the signed wrapper (they were surviving there, stale semantics and all - our own label-drift bug class, caught recurring).

**Changes from v0.1** (unchanged from v0.2): signed wrapper, digests inside the signature, RFC 8785, `iat`, signed errors, digest-based content binding, dual-emit deprecation path. `content_hash`/`content_hash_scope` are superseded by the wrapper digests and MUST NOT appear inside the signed wrapper.

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

Applies to `tools/call` (payload = the result data, byte-identical to the served `structuredContent`) and `resources/read` (payload = the `contents` object). **Nothing may be injected into `structuredContent` that is not in the signed payload** - the served structure and the signed payload are the same bytes under canonicalization, always. The signature attests: this wrapper left this server unaltered, minted at `iat`. Never truth - only origin, integrity, and declared provenance.

## 2. Envelope

In the result's **`_meta`** under the namespaced key:

```json
"result": {
  "resultType": "complete",
  "content": [ { "type": "text", "text": "<human-readable rendering>" } ],
  "structuredContent": <payload>,
  "_meta": {
    "org.jardenberg/verifiable-mcp": {
      "spec": "0.2.1",
      "alg": "EdDSA",
      "kid": "<RFC 7638 JWK thumbprint>",
      "signed": "wrapper",
      "jws": "<compact JWS over the RFC 8785 canonical wrapper>"
    }
  }
}
```

- The JWS protected header MUST carry `typ: "verifiable-mcp+jws"` (RFC 8725 explicit typing). Verifiers MUST reject any other `typ`.
- Anything outside the JWS is convenience-only, never security-bearing; on disagreement the signed value wins.
- Dual-emit of the v0.1 sibling `signature` is deprecated, allowed only at the top-level result (never inside `structuredContent`), removed in v0.3.
- Status: **unnegotiated `_meta` today** - legal under MCP's namespacing, invisible to clients that ignore it. The v1.0 ambition is a negotiated extension with this same reverse-DNS ID via the extensions map; the Extensions Track expects working reference implementations, which is the practical roadmap item.

## 3. Canonicalization: RFC 8785, normatively

The JWS payload is the RFC 8785 (JCS) canonicalization of the wrapper - the RFC, including ECMAScript number serialization, I-JSON conformance, hard errors on lone surrogates. Use a tested JCS library.

## 4. Key discovery

- Entry point: the server card at **`/.well-known/mcp.json`** (the path SEP-2127 settled on, superseding SEP-1649), carrying a `signing` block: `alg`, current `kid`, `previous_kids`, the **`jwks`** key set (inside the signing block), canonicalization statement, `spec: "org.jardenberg/verifiable-mcp"`, `spec_version`. A dedicated key file MAY exist for convenience; the card is normative. The card MUST be fetchable without special headers (no UA-gating).
- `kid` is the RFC 7638 JWK thumbprint. Rotation: publish new alongside old, switch, retire. No revocation protocol in v0.2.1 (§9).
- Optional external anchoring (recommended): fingerprints in a signed git tag, DNS TXT, or a transparency log.

## 5. Provenance block

Inside the signed wrapper. Required: `server_operator`, `canonical_origin` (**a string**; when one response spans several sources, emit a `publishers` array of `{source, content_publisher, canonical_origin}` and omit the top-level `canonical_origin`), `canonical_url` where a single item is returned, `dataset_version` and `last_updated` (both derived from data, never hardcoded), and **exactly one rights field**:

1. `license` - operator owns the content (ensakidag: `CC-BY-4.0`).
2. `legal_basis` - third-party content. Keep the legal claims separate and modest: the *indexing* rests on the EU TDM exception (DSM directive art. 4 - art. 3 is research-organisations-only); the *serving of excerpts* rests on quotation with source attribution. Example string: "Indexed under the EU TDM exception (DSM art. 4); excerpts served with source attribution; all content remains © its publisher." (Not legal advice; consult one before copying this onto your corpus.)
3. `rights` - per-item/per-author (sswcboken: "per author; not Creative Commons").

Human-readable strings in v0.2.1; structured vocabularies (RSL, IETF AI-Pref) are v0.3 work.

**AI-content labeling:** AI-authored material inside the payload carries an explicit inline label, inside the signed scope (sswcboken: "AI-fantasi i författarens anda - INTE författarens egna ord"). Scoped claim, precisely: C2PA manifests already carry signed AI-generation assertions for *media*; what this pattern contributes is **tamper-evident honesty labeling for a text corpus served to agents** - rights and human/AI distinctions inside the signed content payload of an MCP server.

## 6. Content binding - by digest, not by identity

- `content_digest` = SHA-256 over the **UTF-8 bytes of the decoded string value** of `content[0].text` (`contents[0].text` for resources) exactly as served - no Unicode normalization, and JSON wire escaping does not affect it (the digest covers the decoded string, not its escaped serialization).
- When `content` has more than one item, the digest covers item 0; additional items MUST be derivable from `payload` and are consumed at the reader's risk in v0.2.1 (multi-item coverage is a v0.3 candidate).
- The text arm may be prose, markdown, or serialized JSON - any deterministic rendering of `payload`.
- Verifiers consuming the text arm MUST hash what they rendered and compare against the signed `content_digest`; verifiers consuming `structuredContent` compare against the signed `payload` / `payload_digest`. Nothing outside the JWS participates in any check.

## 7. Freshness

`iat` (Unix seconds) in the wrapper; optional `exp`. Stated replay scope: for public archives, `iat` is a freshness signal, not anti-replay. Deployments with real replay risk use the optional `req` request-binding field (client nonce echoed in the wrapper) - specified, out of scope for the reference corpora.

## 8. Errors - both kinds

- **JSON-RPC error frames:** the envelope rides at `error.data["org.jardenberg/verifiable-mcp"]` (strict SDKs drop unknown members beside `code`/`message`; `data` is the sanctioned carrier). Wrapper payload: `{ "id": <request id>, "error": { "code": ..., "message": ... } }`.
- **Tool-level `isError` results:** signed like any tools/call result; wrapper payload = `{ "isError": true, "message": "<the text arm>" }`, `content_digest` over the text arm.
- Where a stack genuinely cannot attach either, the server documents the gap. An unsigned "tool unavailable" is a free lie; don't hand it out.

## 9. Degradation and limits

- No key → serve unsigned rather than not at all; an unsigned response from a signing server is a visible anomaly.
- Signature ≠ truth. The ladder: (1) server authenticity, (2) payload integrity, (3) declared provenance - delivered; (4) source authority, (5) answer fidelity - enabled; (6) truth - never touched. Operator-equals-author (ensakidag) approaches "this archive said this"; a third-party index proves *the index served this representation*.
- Trust root: origin (DNS+TLS) plus optional external anchoring. No revocation, no timestamping authority.
- **Caching:** the 2026-07-28 protocol's `ttlMs`/`cacheScope` hints ride on list operations and `resources/read` (not `tools/call`); a `public`-scoped cached signed *resource* can be served cross-user by a shared gateway and verify perfectly. Harmless for public archives; per-user data needs cache scoping or request binding.
- **Size:** the payload travels twice (structuredContent + base64 in the JWS), three times during dual-emit. Fine for these corpora; detached JWS (RFC 7797) is on the v0.3 list for anyone signing megabytes.
- Adjacent work, named: Web Bot Auth / RFC 9421 (signs the caller and pipe); AP2 (payment mandates); the MCP TBOM discussion #2189 (independently converged on JCS + SHA-256 + JWS - for *tool definitions*); the IETF MCPS draft (ECDSA P-256 + JCS over tool definitions, pin stores, nonces); a C2PA-credentials-via-`_meta` discussion; the peer-reviewed Trustworthy MCP Registry (MDPI Future Internet 18(5):243 - RFC 8615 + Sigstore + JCS/JWS composition for registries); Sirenic, a commercial MCP server whose pitch centers on verifying the signature before reading the provenance. Same ingredients across the field, different targets - this pattern signs the *content payload* of a knowledge corpus with rights and honesty labels inside. The convergence is the point.

## 10. Verifier requirements

A conforming verifier MUST: pin `alg` to `EdDSA` (reject anything else) · resolve `kid` against the discovered JWKS and **fail closed** on a miss (never fall back to "first key") · ignore `jwk`, `jku`, `x5u` and any other key-carrying JWS headers · reject `typ` other than `"verifiable-mcp+jws"` · re-canonicalize with a real JCS library · compare digests against signed values only · treat `isError` results and error frames per §8 (a result without `structuredContent` is not automatically a failure) · send `Mcp-Method`/`Mcp-Name` headers on 2026-07-28 transports (harmless on older servers).

## 11. Conformance

A server conforms to v0.2.1 when: §2 envelope with mandated `typ` · RFC 8785 via tested library · wrapper per §1 with **no `content_hash*` keys** · served `structuredContent` byte-identical (canonically) to signed `payload` · digest binding per §6 · discovery per §4 · §5 provenance with exactly one rights field · AI labels in the signed scope · both error kinds per §8 · unsigned degradation · **published test vectors including negatives**: the set MUST contain a prose text arm case (where `content_digest` ≠ `payload_digest`), a `resources/read` case, an error case, and negative cases (tampered payload byte, unknown kid, wrong alg, mismatched digest) that a conforming verifier MUST reject. Until a stranger can falsify your verifier against known answers - including the answers that must fail - conformance is aspiration, not fact.

*Studio Jardenberg, August 2026. v0.2.1. Feedback: the whole point - this version exists because a reader ran the command.*
