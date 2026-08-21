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

async function runLive(endpoint, tool = "server_info", argsJson = "{}") {
  const origin = endpoint.split("/api/")[0];
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "Mcp-Method": "tools/call", "Mcp-Name": tool },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: tool, arguments: JSON.parse(argsJson) } }),
  });
  const raw = await res.text();
  const msg = raw.includes("data: ")
    ? JSON.parse(raw.split("\n").find((l) => l.startsWith("data: ")).slice(6))
    : JSON.parse(raw);
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
  const card = await (await fetch(origin + "/.well-known/mcp.json")).json();
  const jwks = (card.signing?.jwks ?? card.jwks ?? {}).keys ?? [];
  if (!jwks.length) { console.log("No JWKS discoverable from the server card - failing closed."); process.exit(2); }
  const { payloadBytes } = await verifyJwsStrict(env.jws, jwks);
  const wrapper = JSON.parse(new TextDecoder().decode(payloadBytes));
  console.log("Verifying against live wire:");
  const text = result.content?.[0]?.type === "text" ? result.content[0].text : null;
  checkWrapper(wrapper, payloadBytes, text, true);
  if (result.structuredContent != null && !result.isError) {
    if (canonicalize(wrapper.payload) !== canonicalize(result.structuredContent))
      throw new VerifyError("signed payload != served structuredContent");
    console.log("  [PASS] signed payload == served structuredContent");
  } else if (result.isError) {
    console.log("  [INFO] isError result - signed via the error-wrapper path, no structuredContent expected");
  }
  console.log("ALL CHECKS PASSED (live)");
}

const [mode, arg, tool, args] = process.argv.slice(2);
try {
  if (mode === "--vectors" && arg) await runVectors(arg);
  else if (mode === "--live" && arg) await runLive(arg, tool, args);
  else { console.log("Usage: verify.mjs --vectors <file> | --live <endpoint> [tool] [json-args]"); process.exit(1); }
} catch (e) {
  if (e instanceof VerifyError) { console.log(`  [FAIL] ${e.message}`); process.exit(1); }
  throw e;
}
