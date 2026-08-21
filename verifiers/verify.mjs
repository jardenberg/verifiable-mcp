#!/usr/bin/env node
// verifiable-mcp one-command verifier (spec v0.2)
//
// Offline:  node verify.mjs --vectors ../test-vectors/v0.2.json
// Live:     node verify.mjs --live https://ensakidag.se/api/mcp [tool] [json-args]
//
// Setup: npm install   (jose + canonicalize)
import { readFileSync } from "node:fs";
import { compactVerify, importJWK } from "jose";
import canonicalize from "canonicalize";
import crypto from "node:crypto";

const enc = (s) => new TextEncoder().encode(s);
const sha256hex = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
let failures = 0;
function check(label, ok, detail = "") {
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${label}${detail ? `  (${detail})` : ""}`);
  if (!ok) { failures++; process.exitCode = 1; }
}
const thumbprint = (jwk) =>
  crypto.createHash("sha256")
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))
    .digest("base64url");

async function verifyWrapper(wrapper, envelope, jwk, contentText) {
  const key = await importJWK({ kty: jwk.kty, crv: jwk.crv, x: jwk.x }, "EdDSA");
  const { payload, protectedHeader } = await compactVerify(envelope.jws, key);
  check("JWS signature verifies (EdDSA)", true);
  check("JWS payload == canonical wrapper",
    new TextDecoder().decode(payload) === canonicalize(wrapper));
  check("kid in JWS header matches envelope", protectedHeader.kid === envelope.kid);
  check("payload_digest reproduces (inside signed wrapper)",
    "sha256:" + sha256hex(enc(canonicalize(wrapper.payload))) === wrapper.payload_digest);
  if (contentText != null)
    check("content_digest matches rendered text arm",
      "sha256:" + sha256hex(enc(contentText)) === wrapper.content_digest);
  check("iat present in signed wrapper", Number.isInteger(wrapper.iat));
  check("provenance present with a rights field",
    ["license", "legal_basis", "rights"].some((k) => k in (wrapper.provenance ?? {})));
}

async function runVectors(path) {
  const v = JSON.parse(readFileSync(path, "utf8"));
  console.log(`verifiable-mcp vectors: ${v.spec}`);
  const jwk = v.test_jwk_public;
  check("kid is RFC 7638 thumbprint of test key", thumbprint(jwk) === jwk.kid);
  check("canonical wrapper bytes match published hex",
    Buffer.from(canonicalize(v.wrapper), "utf8").toString("hex") === v.canonical_wrapper_utf8_hex);
  await verifyWrapper(v.wrapper, { jws: v.jws_compact, kid: jwk.kid }, jwk, v.content_text);
  if (!failures) console.log("ALL CHECKS PASSED (offline vectors)");
}

async function runLive(endpoint, tool = "server_info", argsJson = "{}") {
  const origin = endpoint.split("/api/")[0];
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: tool, arguments: JSON.parse(argsJson) } }),
  });
  const raw = await res.text();
  const msg = raw.includes("data: ")
    ? JSON.parse(raw.split("\n").find((l) => l.startsWith("data: ")).slice(6))
    : JSON.parse(raw);
  const result = msg.result ?? {};
  const env = result._meta?.["org.jardenberg.verifiable-mcp"];
  if (!env) {
    if (result.signature) {
      console.log("v0.1 envelope detected (sibling `signature`, no namespaced _meta).");
      console.log("Migration in progress - re-run after the server moves to v0.2.");
      process.exit(2);
    }
    console.log("No signature envelope found - server unsigned (or degradation mode).");
    process.exit(2);
  }
  console.log(`v0.2 envelope found (spec ${env.spec}, kid ${String(env.kid).slice(0, 12)}...)`);
  const card = await (await fetch(origin + "/.well-known/mcp.json")).json();
  const keys = (card.signing?.jwks ?? card.jwks ?? {}).keys ?? [];
  const jwk = keys.find((k) => k.kid === env.kid) ?? keys[0];
  if (!jwk) { console.log("No JWK discoverable from the server card."); process.exit(2); }
  const key = await importJWK({ kty: jwk.kty, crv: jwk.crv, x: jwk.x }, "EdDSA");
  const { payload } = await compactVerify(env.jws, key);
  const wrapper = JSON.parse(new TextDecoder().decode(payload));
  console.log("Verifying against live wire:");
  const text = result.content?.[0]?.type === "text" ? result.content[0].text : null;
  await verifyWrapper(wrapper, env, jwk, text);
  check("wrapper payload == served structuredContent",
    canonicalize(wrapper.payload) === canonicalize(result.structuredContent));
  if (!failures) console.log("ALL CHECKS PASSED (live)");
}

const [mode, arg, tool, args] = process.argv.slice(2);
if (mode === "--vectors" && arg) await runVectors(arg);
else if (mode === "--live" && arg) await runLive(arg, tool, args);
else { console.log("Usage: verify.mjs --vectors <file> | --live <endpoint> [tool] [json-args]"); process.exit(1); }
