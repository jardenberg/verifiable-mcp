#!/usr/bin/env node
// verifiable-mcp one-command verifier (spec v0.2.1)
//
// Offline:  node verify.mjs --vectors ../test-vectors/v0.2.1.json
// Live:     node verify.mjs --live https://ensakidag.se/api/mcp [tool] [json-args]
//
// Setup: npm install   (jose + canonicalize)
//
// Verifier hygiene, per spec S10: alg pinned to EdDSA; typ must be
// "verifiable-mcp+jws"; kid resolved against the discovered JWKS, FAIL CLOSED
// on a miss; jwk/jku/x5u headers rejected; nothing outside the JWS is trusted.
import { readFileSync } from "node:fs";
import { compactVerify, importJWK } from "jose";
import canonicalize from "canonicalize";
import crypto from "node:crypto";

const VERSION = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")).version;
const SPEC_KEY = "org.jardenberg/verifiable-mcp";
const REQUIRED_TYP = "verifiable-mcp+jws";
const enc = (s) => new TextEncoder().encode(s);
const sha256hex = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

class VerifyError extends Error {}

async function verifyJwsStrict(jws, jwks) {
  const [h, p] = jws.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url"));
  if (header.alg !== "EdDSA") throw new VerifyError(`alg pinning: expected EdDSA, got ${JSON.stringify(header.alg)}`);
  if (header.typ !== REQUIRED_TYP) throw new VerifyError(`typ: expected "${REQUIRED_TYP}", got ${JSON.stringify(header.typ)}`);
  for (const banned of ["jwk", "jku", "x5u", "x5c"])
    if (banned in header) throw new VerifyError(`key-carrying header "${banned}" present; keys only come from discovery`);
  const jwk = jwks.find((k) => k.kid === header.kid);
  if (!jwk) throw new VerifyError(`kid ${JSON.stringify(header.kid)} not in discovered JWKS - failing closed`);
  const key = await importJWK({ kty: jwk.kty, crv: jwk.crv, x: jwk.x }, "EdDSA");
  const { payload } = await compactVerify(jws, key);
  return { header, payloadBytes: payload };
}

function checkWrapper(wrapper, payloadBytes, contentText, verbose = false) {
  const ok = (label) => { if (verbose) console.log(`  [PASS] ${label}`); };
  if (new TextDecoder().decode(payloadBytes) !== canonicalize(wrapper))
    throw new VerifyError("JWS payload != canonical wrapper");
  ok("JWS verifies; payload == canonical wrapper (typ, alg, kid all strict)");
  if (!Number.isInteger(wrapper.iat)) throw new VerifyError("iat missing from signed wrapper");
  for (const banned of ["content_hash", "content_hash_alg", "content_hash_scope"])
    if (banned in (wrapper.provenance ?? {}))
      throw new VerifyError(`v0.1 field "${banned}" inside signed wrapper (banned in v0.2.1)`);
  if ("sha256:" + sha256hex(enc(canonicalize(wrapper.payload))) !== wrapper.payload_digest)
    throw new VerifyError("payload_digest does not reproduce");
  ok("payload_digest reproduces (inside signed wrapper)");
  if (contentText != null) {
    if ("sha256:" + sha256hex(enc(contentText)) !== wrapper.content_digest)
      throw new VerifyError("content_digest does not match the served text arm");
    ok("content_digest matches the served text arm bytes");
  }
  const rights = ["license", "legal_basis", "rights"].filter((k) => k in (wrapper.provenance ?? {}));
  if (!("error" in (wrapper.payload ?? {})) && rights.length !== 1)
    throw new VerifyError(`provenance must carry exactly one rights field, found [${rights}]`);
  ok("iat present; no v0.1 content_hash* fields; exactly one rights field");
}

async function runVectors(path) {
  const v = JSON.parse(readFileSync(path, "utf8"));
  if (!v.spec_version || !v.cases) {
    console.log("This is a v0.2-format vector file (single case, superseded).");
    console.log("Use test-vectors/v0.2.1.json - the current set with negatives.");
    process.exit(2);
  }
  console.log(`verifiable-mcp vectors: ${v.spec} v${v.spec_version} - ${v.cases.length} cases`);
  let unexpected = 0;
  for (const c of v.cases) {
    let outcome = "pass", detail = "";
    try {
      const { payloadBytes } = await verifyJwsStrict(c.jws, v.jwks.keys);
      checkWrapper(c.wrapper, payloadBytes, c.content_text ?? null);
    } catch (e) { outcome = "fail"; detail = e.message; }
    const ok = outcome === c.expect;
    console.log(`  [${ok ? "PASS" : "UNEXPECTED"}] ${c.name}: verified=${outcome === "pass"}`
      + (detail && ok ? `  (${detail})` : "") + (ok ? "" : `  EXPECTED ${c.expect}`));
    if (!ok) unexpected++;
  }
  if (unexpected) { console.log(`${unexpected} case(s) behaved unexpectedly`); process.exit(1); }
  console.log("ALL CASES BEHAVED AS EXPECTED (positives verify, negatives rejected)");
}

async function runLive(endpoint, tool = "server_info", argsJson = "{}", protocolVersion = "2025-11-25", expectError = false) {
  const url = new URL(endpoint);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password)
    throw new VerifyError("endpoint must be an HTTP(S) URL without credentials");
  const origin = url.origin;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "Mcp-Method": "tools/call", "Mcp-Name": tool,
               "MCP-Protocol-Version": protocolVersion,
               "User-Agent": `verifiable-mcp-verifier/${VERSION}` },
    signal: AbortSignal.timeout(30000),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: tool, arguments: JSON.parse(argsJson) } }),
  });
  const raw = await res.text();
  let msg;
  if (raw.trimStart().startsWith("{")) msg = JSON.parse(raw);
  else {
    for (const event of raw.replaceAll("\r\n", "\n").split("\n\n")) {
      const data = event.split("\n").filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).replace(/^ */, "")).join("\n");
      if (!data.trim()) continue;
      const candidate = JSON.parse(data);
      if (candidate.id === 1) { msg = candidate; break; }
    }
    if (!msg) throw new VerifyError("no matching JSON-RPC response in event stream");
  }
  if (msg.jsonrpc !== "2.0" || msg.id !== 1 || (("result" in msg) === ("error" in msg)))
    throw new VerifyError("invalid or mismatched JSON-RPC response");
  const result = msg.result ?? {};
  const env = result._meta?.[SPEC_KEY] ?? msg.error?.data?.[SPEC_KEY];
  if (!env) {
    if (result.signature) {
      console.log("v0.1 envelope detected (sibling `signature`, no namespaced _meta).");
      console.log("Migration in progress - re-run after the server moves to v0.2.1.");
      process.exit(2);
    }
    console.log("No signature envelope found - server unsigned (or degradation mode).");
    process.exit(2);
  }
  console.log(`v0.2 envelope found (spec ${env.spec}, kid ${String(env.kid).slice(0, 12)}...)`);
  const cardResponse = await fetch(origin + "/.well-known/mcp.json", {
    headers: { "User-Agent": `verifiable-mcp-verifier/${VERSION}` }, signal: AbortSignal.timeout(20000),
  });
  if (!cardResponse.ok) throw new VerifyError(`discovery returned HTTP ${cardResponse.status}`);
  const card = await cardResponse.json();
  const jwks = (card.signing?.jwks ?? card.jwks ?? {}).keys ?? [];
  if (!jwks.length) { console.log("No JWKS discoverable from the server card - failing closed."); process.exit(2); }
  const { payloadBytes } = await verifyJwsStrict(env.jws, jwks);
  const wrapper = JSON.parse(new TextDecoder().decode(payloadBytes));
  console.log("Verifying against live wire:");
  const text = result.content?.[0]?.type === "text" ? result.content[0].text : null;
  checkWrapper(wrapper, payloadBytes, text, true);
  const isError = "error" in msg || result.isError === true;
  let expected;
  if ("error" in msg) expected = { id: msg.id, error: { code: msg.error.code, message: msg.error.message } };
  else if (result.isError === true) {
    if (text === null) throw new VerifyError("tool error has no text arm");
    expected = { isError: true, message: text };
  } else {
    if (!res.ok) throw new VerifyError(`successful tool result returned HTTP ${res.status}`);
    if (!("structuredContent" in result) || text === null)
      throw new VerifyError("successful tool result requires structuredContent and a text arm");
    expected = result.structuredContent;
  }
  if (canonicalize(wrapper.payload) !== canonicalize(expected))
    throw new VerifyError("signed payload != served result or error");
  console.log("  [PASS] signed payload == served result or error");
  if (isError !== expectError)
    throw new VerifyError(isError ? "signed error verified, but tool call failed (use --expect-error to test errors)"
      : "expected a signed error, but tool call succeeded");
  console.log(isError ? "ALL CHECKS PASSED (live signed error; tool did not succeed)"
    : "ALL CHECKS PASSED (live successful tool result)");
}

try {
  const positional = [];
  let protocolVersion = "2025-11-25", expectError = false;
  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    if (arg === "--version") { console.log(`verifiable-mcp tooling ${VERSION}; spec 0.2.1`); process.exit(0); }
    if (arg === "--expect-error") expectError = true;
    else if (arg === "--protocol-version") {
      protocolVersion = process.argv[++i];
      if (!protocolVersion || protocolVersion.startsWith("--")) throw new VerifyError("--protocol-version requires a value");
    } else positional.push(arg);
  }
  const [mode, arg, tool, args] = positional;
  if (mode === "--vectors" && arg && positional.length === 2) await runVectors(arg);
  else if (mode === "--live" && arg && positional.length <= 4) await runLive(arg, tool, args, protocolVersion, expectError);
  else { console.log("Usage: verify.mjs --version | --vectors <file> | --live <endpoint> [tool] [json-args] [--protocol-version VERSION] [--expect-error]"); process.exit(1); }
} catch (e) {
  console.error(`  [FAIL] ${e.message}`); process.exit(1);
}
