# Changelog

## Unreleased
- Companion essay added ([ESSAY.md](ESSAY.md)): "Why should an agent believe
  you?" - the argument in prose, published once all three reference servers
  went live at v0.2.1 and wire-verified with the repo verifier.

## v0.2.1 (2026-08-21) - conformance release

Driven by an external reviewer who did what the pattern asks: ran the published
verifier against the live servers and reported what broke. Thank you.

### Spec
- **`_meta` key renamed**: `org.jardenberg.verifiable-mcp` → `org.jardenberg/verifiable-mcp`
  (MCP's namespaced-key grammar: reverse-DNS prefix, slash, name).
- **JWS `typ` mandated**: `"verifiable-mcp+jws"` (RFC 8725 explicit typing);
  verifiers reject anything else.
- **Error envelope carrier**: JSON-RPC error frames carry the envelope at
  `error.data[...]` (strict SDKs drop unknown members beside code/message).
  Tool-level `isError` results defined: wrapper payload `{isError, message}`.
- **`canonical_origin` is a string**; multi-source responses use `publishers[]`.
- **`content_digest` made byte-precise**: UTF-8 bytes of the decoded string
  value, no Unicode normalization; multi-item `content` behavior stated.
- **Verifier requirements (S10)**: pinned alg, fail-closed kid resolution,
  key-carrying headers rejected, typ enforcement, Mcp-Method/Mcp-Name headers.
- `content_hash`/`content_hash_alg`/`content_hash_scope` explicitly banned
  inside the signed wrapper (v0.1 debris was surviving there - our own
  label-drift bug class, caught recurring by the reviewer).
- Discovery note corrected: SEP-2127 settled `/.well-known/mcp.json`.
- Caching note corrected: `ttlMs`/`cacheScope` ride on list operations and
  `resources/read`, not `tools/call`.
- Legal-basis guidance split: TDM (DSM art. 4) covers indexing; serving
  excerpts rests on quotation with attribution. Not legal advice.
- Neighbors added: MCP TBOM discussion #2189, IETF MCPS draft.
- AI-labeling contribution claim scoped: "for a text corpus served to agents".

### Vectors
- v0.2.1 set: 4 positives (JSON arm, **prose arm** - exercising the digest
  binding specifically, resources/read, error frame) + 5 negatives (tampered
  payload, unknown kid, wrong alg, mismatched content digest, wrong typ).
  Negatives MUST be rejected by a conforming verifier.

### Verifiers
- Fail closed on unknown `kid` (previously fell back to the first JWKS key -
  a fail-open bug, found by the reviewer).
- Alg pinned to EdDSA before any signature math; `typ` enforced;
  `jwk`/`jku`/`x5u`/`x5c` headers rejected.
- Tolerate `isError` results (no `structuredContent` expected) and find error
  envelopes at `error.data`.
- Send `Mcp-Method`/`Mcp-Name` on live calls (2026-07-28 transports).
- Reject v0.1 `content_hash*` fields inside signed wrappers.

## v0.2 (2026-08-21)
Initial public release: signed wrapper, digests inside the signature,
namespaced `_meta` envelope, RFC 8785, digest-based content binding, signed
errors, dual-emit v0.1 deprecation, first vector + two verifiers.
