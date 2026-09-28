# Reference verification, 28 September 2026

Tooling release **0.2.2**, signing specification **0.2.1**. Rollback baseline:
[`b00b001`](https://github.com/jardenberg/verifiable-mcp/commit/b00b0015a7b875b3f2019d6f49a92d1f85e75766).

## Results

| Endpoint | Successful tool | MCP protocol header | Python | Node |
|---|---|---|---|---|
| https://ensakidag.se/api/mcp | `server_info` | 2025-11-25 | Pass | Pass |
| https://rise-ai-sweden.jardenberg.org/api/mcp | `server_info` | 2025-11-25 | Pass | Pass |
| https://sswcboken.se/api/mcp | `server_info` | 2025-06-18 | Pass | Pass |
| https://joakim.jardenberg.net/mcp | `ppcp_get_version` | 2025-11-25 | Pass | Pass |
| https://hkdemo.jardenberg.net/api/mcp | `hallbarhetsklivet_get_status` | 2025-11-25 | Pass | Pass |

[Timestamped CLI results](results.json) link to each retained log. All five
responses used the v0.2.1 envelope. Neither verifier required a local transport
patch. The tools and protocol headers are explicit, so a signed unknown-tool
or unsupported-protocol error cannot masquerade as a successful read.

[Independent binding results](independent-bindings.json) retain each endpoint,
discovery URL, complete key ID, advertised previous keys, signed provenance,
response digest and link to the captured public server card and response.
The separate checker uses Python's cryptography and RFC 8785 libraries without
importing either shipped verifier. It reproduces the Ed25519 signature,
canonical wrapper, payload equality, payload digest, exact text digest and
RFC 7638 key thumbprint, and checks required provenance and one rights field.
It is a separate implementation check by the same maintainer, not a third-party audit.

## Local regression evidence

- Both verifiers: all nine published v0.2.1 vectors produced the expected result,
  including rejection of all five negative cases.
- 44 CLI scenarios: endpoint paths, query strings, trailing slashes, required
  protocol headers, custom revisions, SSE heartbeats and notifications,
  successful tools versus both error types, HTTP error bodies, altered text,
  altered payloads, altered error messages, missing result arms, mismatched
  response IDs, ambiguous result/error messages and unsigned responses.
- The successful fixture includes fractional numbers and Unicode property names
  whose ordering differs between ordinary Python JSON sorting and RFC 8785.
- Both `--version` outputs identify tooling 0.2.2 and signing spec 0.2.1.

Reproduce from the repository root after the README dependency setup:

```bash
.venv/bin/python verifiers/verify.py --vectors test-vectors/v0.2.1.json
node verifiers/verify.mjs --vectors test-vectors/v0.2.1.json
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python verification/check_live.py
.venv/bin/python verification/capture_reference_evidence.py
```

Live scripts write a directory for the current UTC date. Retained responses are
public status/version data, not credentials. Test signing uses only the
explicitly public fixture key from the published vector file.

The first independent capture attempt assumed JSON and stopped on an SSE response.
Its parser was corrected to accept the matching event-stream response; the
completed capture above passed. Neither shipped verifier failed that live check.

## Limits

These checks establish successful signed responses at the recorded times. They
do not certify every tool, resource, error path, key rotation, unsigned
fallback, host refresh, source licence, publisher endorsement or factual claim.
Error-path regressions here use local fixtures; this release did not remove
production signing keys or change any reference server. Discovery was fetched
with named verifier/audit user agents, not every possible client user agent.
The CLIs probe stateless public endpoints directly and do not implement session
initialization, authentication, replay protection or continuous monitoring.
