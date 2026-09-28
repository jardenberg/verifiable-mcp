# Changelog

## Tooling v0.2.2 (2026-09-28) - implementation lessons and five reference examples

Signing specification and published v0.2.1 vectors are unchanged. Tooling version
is recorded in `verifiers/package.json` and exposed by both CLIs with `--version`.

### Fixed
- Both live verifiers discover the server card at the URL origin, including
  endpoints at `/mcp`, nested paths, trailing slashes and query strings.
- Send an explicit MCP protocol-version header, defaulting to `2025-11-25`,
  with `--protocol-version` for other supported revisions.
- A valid signed error no longer counts as a successful tool call. Deliberate
  error tests use `--expect-error`; signed payloads must match the served
  JSON-RPC error or tool-level error. HTTP error bodies remain verifiable.
- Require matching JSON-RPC response IDs and an unambiguous result/error shape.
  SSE parsing skips empty events and notifications before the matching response.
- Python requires real RFC 8785 canonicalization instead of silently using
  sorted-key JSON, which is incorrect for some numbers and Unicode keys.

### Added
- PPCP and the independent Hållbarhetsklivet demo alongside the original three
  reference implementations, with distinct rights and authority explanations.
- Dated public evidence: both CLIs verified a successful response from all five
  endpoints; independent checks reproduced signed bindings and key thumbprints.
- 44 local CLI regression scenarios plus CI for both verifiers and all nine
  existing positive/negative vectors. Live network checks remain opt-in.

### Changed
- Replaced the blanket migration statement with dated, explicitly scoped
  verification results. One successful response is not full server conformance.
- Documented the direct stateless probe scope, dependency setup, explicit tool
  selection and separate signing-spec/tooling versions.

## Historical documentation update (2026-08-22; reconstructed from Git history)
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
