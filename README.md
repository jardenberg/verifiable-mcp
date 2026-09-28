# verifiable-mcp

**Signed, sourced, reproducible.** A working pattern for cryptographically verifiable MCP responses: every `tools/call` and `resources/read` answer carries provenance (origin, rights, freshness) and an Ed25519 signature - portable, offline-checkable attribution for knowledge corpora in the agent era. C2PA-spirit, applied to tool output.

**Status: Experimental. Signing spec v0.2.1; tooling release v0.2.2 (2026-09-28).** The signed format is unchanged. [Changelog](CHANGELOG.md) · [Release metadata](verifiers/package.json)

## Reference implementations

| Server | Knowledge source | Declared rights and authority | What this demonstrates |
|---|---|---|---|
| [ensakidag.se](https://ensakidag.se/mcp) | Personal podcast archive | Original content under CC BY 4.0; operator is the author | First-party archive provenance, with human source material distinguished from AI commentary |
| [RISE + AI Sweden index](https://rise-ai-sweden.jardenberg.org) | Third-party AI publications | Declared indexing basis and attributed excerpts; no ownership of publisher content claimed | The index signs the representation it serves, while identifying the upstream sources |
| [sswcboken.se](https://sswcboken.se/mcp) | Multi-author book archive with an AI-reply layer | Per-author rights; not Creative Commons | Human writing and explicitly labelled AI replies share a verifiable delivery format |
| [PPCP: Joakim Jardenberg](https://joakim.jardenberg.net/mcp) | A living, owner-approved public personal profile, with section retrieval and source pointers | Original profile text under CC BY 4.0; third-party exceptions; AI-assisted editorial authorship and declared owner approval | A person publishes evolving public context with explicit authorship, approval and authority boundaries. Reading it grants no authority to act or speak for them |
| [Hållbarhetsklivet demo](https://hkdemo.jardenberg.net/) | Swedish tourism and sustainability knowledge, including practical examples and participating organisations | Third-party rights retained; independently indexed, source-linked excerpts; no publisher endorsement or open licence asserted | Practical discovery of sector knowledge in an AI assistant, with the independent service operator distinguished from the original publisher |

Different knowledge sources, rights and authority relationships. One verification pattern.

The differentiator is what sits *inside* the signed scope: source provenance, rights declarations and human/AI distinctions. In the book archive, an AI reply is labelled as imagined writing, not the author's own words. In PPCP, AI-assisted editorial wording and declared owner approval travel with the profile. A signature makes these declarations tamper-evident; it does not independently establish their truth.

Hållbarhetsklivet is an independent demonstration using material from [hallbarhetsklivet.se](https://hallbarhetsklivet.se/). It shows how existing knowledge can become useful through an assistant people already use. The demonstration is not an official publisher service or an endorsement.

**Checked 28 September 2026:** both verifiers passed one successful signed tool response from each of the five endpoints. An independent check also reproduced the signatures, key thumbprints, payload equality, digests and provenance checks. [Dated results, commands and limits](verification/2026-09-28/REPORT.md). This is evidence for those responses, not certification of every tool, error path or client. Some servers retain legacy sibling fields; the checks use the v0.2.1 envelope.

## Verify in one command

From the repository root, install the dependencies:

```bash
# Python 3.11+; both cryptography and real RFC 8785 canonicalization are required
python3 -m venv .venv
.venv/bin/pip install -r verifiers/requirements.txt

# Node 18+
npm install --prefix verifiers --ignore-scripts
```

Against the published test vectors (offline after installation):

```bash
.venv/bin/python verifiers/verify.py --vectors test-vectors/v0.2.1.json
node verifiers/verify.mjs --vectors test-vectors/v0.2.1.json
```

Against the reference endpoints (either verifier accepts the same arguments):

```bash
.venv/bin/python verifiers/verify.py --live https://ensakidag.se/api/mcp server_info
.venv/bin/python verifiers/verify.py --live https://rise-ai-sweden.jardenberg.org/api/mcp server_info
node verifiers/verify.mjs --live https://sswcboken.se/api/mcp server_info --protocol-version 2025-06-18
node verifiers/verify.mjs --live https://joakim.jardenberg.net/mcp ppcp_get_version
node verifiers/verify.mjs --live https://hkdemo.jardenberg.net/api/mcp hallbarhetsklivet_get_status
```

The live check calls the named tool, discovers keys at the endpoint's origin, verifies the JWS over the RFC 8785 canonical wrapper, reproduces both digests, and compares the signed payload with the served result. Unknown keys, wrong algorithms, wrong signature types and altered content fail closed. The Python verifier no longer falls back to ordinary JSON sorting when RFC 8785 is unavailable.

These are bounded, direct probes of public stateless endpoints, not a general MCP client: they do not initialize sessions, authenticate or negotiate protocol revisions. The default `MCP-Protocol-Version` header is `2025-11-25`; use `--protocol-version` for a revision supported by the server. Discovery works for `/mcp`, `/api/mcp` and other endpoint paths. The discovery origin comes from the endpoint URL, not from a source publisher named in provenance.

**A verified error is still an error.** By default, `--live` returns a nonzero exit status if the tool fails, even when its error signature is valid. To deliberately test a signed JSON-RPC or tool-level error, add `--expect-error`. That mode checks the error's signature and binding to the served error, and fails if the tool unexpectedly succeeds. HTTP 4xx error bodies can be verified too. A legacy-only v0.1 envelope is reported separately and does not pass.

Run the local transport regressions, including signed errors and tampering:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## What a signature proves - and what it never can

A ladder: (1) server authenticity, (2) payload integrity, (3) declared provenance - **delivered**. It *enables* (4) source authority and (5) answer fidelity checks. It never touches (6) **truth**. When operator and author coincide, a verified response approaches "this person's archive said this"; for a third-party index it proves *the index served this representation* - not that the upstream publisher wrote those words. The spec says exactly what it can prove, and no more. That is the approach.

## Why

The companion essay, [Why should an agent believe you?](ESSAY.md), makes the argument in prose: the agentic web runs on an honor system, and honor systems do not scale. Read it with a terminal open - the closing line means it.

## Spec

Read [SPEC.md](SPEC.md) - envelope in namespaced `_meta`, signed wrapper `{iat, payload, payload_digest, content_digest, provenance}`, RFC 8785 canonicalization, digest-based content binding, key discovery, rights semantics, signed errors, degradation rule, limits (including the honest ones: no revocation, iat is freshness not anti-replay, trust root is origin+optional external anchor).

## Conformance

Run the [checklist](CHECKLIST.md) against your own corpus. **The specific ask: if you operate a corpus agents will quote - an archive, a museum, a municipality - implement the pattern, run the checklist, and [tell us what broke in Discussions](https://github.com/jardenberg/verifiable-mcp/discussions).** (Email works too: joakim@jardenberg.com.) Three strangers reproducing this is worth more than any launch post - and a public trail of conformance reports is the point of the pattern.

## Adjacent work (who else looked)

Web Bot Auth / RFC 9421 sign the caller and the pipe. AP2 signs payment mandates. The MCP TBOM discussion (#2189) independently converged on JCS + SHA-256 + JWS - for tool definitions; the IETF MCPS draft signs tool definitions with ECDSA P-256 + JCS. An open MCP discussion proposes C2PA credentials via `_meta`. The peer-reviewed Trustworthy MCP Registry work (MDPI, Future Internet 18(5):243) composes well-known discovery + Sigstore + JCS/JWS for registries. Sirenic ships a commercial MCP server whose pitch centers on verifying the signature before reading the provenance. None sign the content payload of a knowledge corpus with rights and honesty labels inside the envelope - and the independent convergence is the point: the problem is real.

## License

MIT for the specification text, verifiers, tests and documentation. The corpora behind the reference servers, and captured server responses retained as verification evidence, keep their declared rights. See each server's signed provenance.

---

*Studio Jardenberg, 2026. Built almost entirely by talking to AI, verified from outside at every step - the method travels with the pattern.*
