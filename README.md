# verifiable-mcp

**Signed, sourced, reproducible.** A working pattern for cryptographically verifiable MCP responses: every `tools/call` and `resources/read` answer carries provenance (origin, rights, freshness) and an Ed25519 signature - portable, offline-checkable attribution for knowledge corpora in the agent era. C2PA-spirit, applied to tool output.

**Status: Experimental, spec v0.2.1.** Three reference servers run this in production (migrating v0.1 → v0.2.1, dual-emitting during the window):

| Server | Corpus | Rights model |
|---|---|---|
| [ensakidag.se](https://ensakidag.se/mcp) | 500-episode personal podcast archive | `license: CC-BY-4.0` (operator owns content) |
| [rise-ai-sweden.jardenberg.org](https://rise-ai-sweden.jardenberg.org) | Index of RISE + AI Sweden AI publications | `legal_basis: EU TDM exception` (third-party, no rights claimed) |
| [sswcboken.se](https://sswcboken.se/mcp) | 181 texts by 184 authors (2010) + AI-reply layer | `rights: per author; not Creative Commons` |

Three corpora, three rights situations, one spec. The differentiator is not the cryptography - it is what sits *inside* the signed scope: rights declarations and AI-content labels ("AI-fantasi i författarens anda - INTE författarens egna ord"), making the human/AI distinction itself tamper-evident.

## Verify in one command

Against the published test vectors (offline, no network):

```bash
# Python (needs: pip install cryptography; optional: rfc8785)
python3 verifiers/verify.py --vectors test-vectors/v0.2.1.json

# Node 18+
cd verifiers && npm install && node verify.mjs --vectors ../test-vectors/v0.2.1.json
```

Against a live server:

```bash
python3 verifiers/verify.py --live https://ensakidag.se/api/mcp
node verifiers/verify.mjs --live https://sswcboken.se/api/mcp
```

The live check calls one tool, extracts the `_meta["org.jardenberg/verifiable-mcp"]` envelope, fetches the server's published key, verifies the JWS over the RFC 8785 canonical wrapper, and reproduces both digests - failing closed on unknown kids, wrong alg, or wrong typ. If it finds only a v0.1 envelope (sibling `signature` object), it says so: migration in progress, not absence.

## What a signature proves - and what it never can

A ladder: (1) server authenticity, (2) payload integrity, (3) declared provenance - **delivered**. It *enables* (4) source authority and (5) answer fidelity checks. It never touches (6) **truth**. When operator and author coincide, a verified response approaches "this person's archive said this"; for a third-party index it proves *the index served this representation* - not that the upstream publisher wrote those words. The spec says exactly what it can prove, and no more. That is the approach.

## Why

The companion essay, [Why should an agent believe you?](ESSAY.md), makes the argument in prose: the agentic web runs on an honor system, and honor systems do not scale. Read it with a terminal open - the closing line means it.

## Spec

Read [SPEC.md](SPEC.md) - envelope in namespaced `_meta`, signed wrapper `{iat, payload, payload_digest, content_digest, provenance}`, RFC 8785 canonicalization, digest-based content binding, key discovery, rights semantics, signed errors, degradation rule, limits (including the honest ones: no revocation, iat is freshness not anti-replay, trust root is origin+optional external anchor).

## Conformance

Run the [checklist](CHECKLIST.md) against your own corpus. **The specific ask: if you operate a corpus agents will quote - an archive, a museum, a municipality - implement the pattern, run the checklist, and [tell us what broke](mailto:joakim@jardenberg.com).** Three strangers reproducing this is worth more than any launch post.

## Adjacent work (who else looked)

Web Bot Auth / RFC 9421 sign the caller and the pipe. AP2 signs payment mandates. The MCP TBOM discussion (#2189) independently converged on JCS + SHA-256 + JWS - for tool definitions; the IETF MCPS draft signs tool definitions with ECDSA P-256 + JCS. An open MCP discussion proposes C2PA credentials via `_meta`. The peer-reviewed Trustworthy MCP Registry work (MDPI, Future Internet 18(5):243) composes well-known discovery + Sigstore + JCS/JWS for registries. Sirenic ships a commercial MCP server whose pitch centers on verifying the signature before reading the provenance. None sign the content payload of a knowledge corpus with rights and honesty labels inside the envelope - and the independent convergence is the point: the problem is real.

## License

MIT for everything in this repository (spec text, verifiers, vectors). The corpora behind the reference servers keep their own rights - see each server's provenance.

---

*Studio Jardenberg, 2026. Built almost entirely by talking to AI, verified from outside at every step - the method travels with the pattern.*
