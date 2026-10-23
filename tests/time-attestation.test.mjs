import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { authorizeLiveRemoteTime, consumeTimeAttestation, createTimeAttestationEnvelope, verifyTimeAttestationEnvelope } from "../scripts/time-attestation.mjs";
import { createTrustBundleEnvelope } from "../scripts/trust-bundle.mjs";

const payload = { schemaVersion: 1, product: "Fixture", environment: "production", evaluationId: "evaluation-123", nonce: "1".repeat(64), authorityRunId: "2".repeat(64), observedAt: "2030-01-01T00:00:00.000Z" };
const sha = (value) => createHash("sha256").update(value).digest("hex");
const trustEntry = (key) => { const publicKey = key.type === "public" ? key : createPublicKey(key); const der = publicKey.export({ type: "spki", format: "der" }); return { keyId: sha(der), publicKeySpkiBase64: der.toString("base64") }; };

test("verifies a signed remote clock without consulting the local clock", () => {
  const key = generateKeyPairSync("ed25519"); const envelope = createTimeAttestationEnvelope(payload, key.privateKey); const verified = verifyTimeAttestationEnvelope(Buffer.from(JSON.stringify(envelope)), key.publicKey, { product: payload.product, environment: payload.environment, evaluationId: payload.evaluationId, nonce: payload.nonce });
  assert.equal(verified.clock.source, "signed-remote"); assert.equal(verified.clock.observedAt, payload.observedAt); assert.equal(verified.clock.milliseconds, Date.parse(payload.observedAt));
});

test("rejects time substitution, wrong scope, and an untrusted authority", () => {
  const key = generateKeyPairSync("ed25519"); const other = generateKeyPairSync("ed25519"); const envelope = createTimeAttestationEnvelope(payload, key.privateKey); const bytes = Buffer.from(JSON.stringify(envelope));
  assert.throws(() => verifyTimeAttestationEnvelope(bytes, other.publicKey), /not trusted/); assert.throws(() => verifyTimeAttestationEnvelope(bytes, key.publicKey, { evaluationId: "other-evaluation" }), /evaluationId mismatch/);
  const modified = structuredClone(envelope); const decoded = JSON.parse(Buffer.from(modified.payload, "base64")); decoded.observedAt = "2040-01-01T00:00:00.000Z"; modified.payload = Buffer.from(JSON.stringify(decoded)).toString("base64"); assert.throws(() => verifyTimeAttestationEnvelope(Buffer.from(JSON.stringify(modified)), key.publicKey), /signature is invalid/);
});

test("atomically consumes a time nonce once", async () => {
  const key = generateKeyPairSync("ed25519"); const verified = verifyTimeAttestationEnvelope(Buffer.from(JSON.stringify(createTimeAttestationEnvelope(payload, key.privateKey))), key.publicKey); const ledger = await mkdtemp(path.join(tmpdir(), "anti-rea-time-ledger-"));
  const first = await consumeTimeAttestation(ledger, verified, payload.evaluationId); assert.equal(first.nonce, payload.nonce); await assert.rejects(() => consumeTimeAttestation(ledger, verified, payload.evaluationId), /already consumed/);
});

test("creates an unpredictable live challenge and rejects a cached authority response", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-live-time-")); const ledger = path.join(directory, "ledger"); await mkdir(ledger); const authority = generateKeyPairSync("ed25519"); const root = generateKeyPairSync("ed25519"); const now = Date.now();
  const trustBundleBytes = Buffer.from(JSON.stringify(createTrustBundleEnvelope({ schemaVersion: 1, bundleId: "live-time-roots", product: "Fixture", environment: "production", issuedAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 60 * 60 * 1000).toISOString(), roles: { "time-authority": [trustEntry(authority.publicKey)] } }, root.privateKey)));
  const cache = path.join(directory, "cached-response.json"); const client = path.join(directory, "authority-client.mjs"); const modulePath = path.resolve(import.meta.dirname, "..", "scripts", "time-attestation.mjs"); const privatePem = authority.privateKey.export({ type: "pkcs8", format: "pem" });
  await writeFile(client, `#!/usr/bin/env node\nimport fs from "node:fs";import crypto from "node:crypto";import {createTimeAttestationEnvelope} from ${JSON.stringify(modulePath)};const cache=${JSON.stringify(cache)};if(fs.existsSync(cache)){process.stdout.write(fs.readFileSync(cache));process.exit(0)}let input="";for await(const chunk of process.stdin)input+=chunk;const request=JSON.parse(input);const envelope=createTimeAttestationEnvelope({schemaVersion:1,product:request.product,environment:request.environment,evaluationId:request.evaluationId,nonce:request.nonce,authorityRunId:crypto.randomBytes(32).toString("hex"),observedAt:new Date().toISOString()},${JSON.stringify(privatePem)});const bytes=JSON.stringify(envelope);fs.writeFileSync(cache,bytes);process.stdout.write(bytes);\n`); await chmod(client, 0o755);
  const first = await authorizeLiveRemoteTime({ trustBundleBytes, trustRootPublicKeyBytes: root.publicKey.export({ type: "spki", format: "pem" }), product: "Fixture", evaluationId: "live-evaluation", authorityClient: client, ledgerRoot: ledger });
  assert.equal(first.clock.source, "signed-live"); assert.match(first.request.nonce, /^[a-f0-9]{64}$/); assert.match(first.clock.requestSha256, /^[a-f0-9]{64}$/);
  await assert.rejects(authorizeLiveRemoteTime({ trustBundleBytes, trustRootPublicKeyBytes: root.publicKey.export({ type: "spki", format: "pem" }), product: "Fixture", evaluationId: "live-evaluation", authorityClient: client, ledgerRoot: ledger }), /nonce mismatch/);
});

const FAULT_AUTHORITY_TIMEOUT_MS = 5000;

async function runFaultyAuthority(body, timeoutMs = FAULT_AUTHORITY_TIMEOUT_MS) {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-time-fault-"));
  const client = path.join(directory, "authority.mjs"); const ledger = path.join(directory, "ledger");
  const ready = path.join(directory, "client-started");
  await mkdir(ledger); await writeFile(client, `#!${process.execPath}\nimport {writeFileSync} from "node:fs";writeFileSync(${JSON.stringify(ready)},"ready");\n${body}\n`); await chmod(client, 0o755);
  const authority = generateKeyPairSync("ed25519"); const root = generateKeyPairSync("ed25519"); const now = Date.now();
  const bundle = createTrustBundleEnvelope({ schemaVersion: 1, bundleId: "fault-time-roots", product: "Fixture", environment: "production", issuedAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 60 * 60 * 1000).toISOString(), roles: { "time-authority": [trustEntry(authority.publicKey)] } }, root.privateKey);
  const options = { trustBundleBytes: JSON.stringify(bundle), trustRootPublicKeyBytes: root.publicKey.export({ type: "spki", format: "pem" }), product: "Fixture", evaluationId: "fault-evaluation", authorityClient: client, ledgerRoot: ledger, timeoutMs };
  const runner = `import {authorizeLiveRemoteTime} from ${JSON.stringify(new URL("../scripts/time-attestation.mjs", import.meta.url).href)};
    import {existsSync} from "node:fs";
    let ticked=false;setTimeout(()=>{ticked=true},10);const start=performance.now();
    try {await authorizeLiveRemoteTime(${JSON.stringify(options)});console.log(JSON.stringify({accepted:true}));}
    catch(error){console.log(JSON.stringify({message:error.message,elapsed:performance.now()-start,ticked,ready:existsSync(${JSON.stringify(ready)})}));}`;
  try {
    return await new Promise((resolve, reject) => {
      // A separate watchdog still runs if a regression restores blocking spawnSync.
      // All hostile fixtures also exit by themselves after ten seconds, beyond
      // the eight-second watchdog, so a blocking regression still fails.
      const child = spawn(process.execPath, ["--input-type=module", "-e", runner], { detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] });
      let stdout = ""; let stderr = "";
      const timer = setTimeout(() => {
        try { if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL"); else child.kill("SIGKILL"); } catch {}
        child.stdout.destroy(); child.stderr.destroy(); child.unref();
        reject(new Error("outer watchdog: time authority did not respect its deadline"));
      }, timeoutMs + 3000);
      child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", (error) => { clearTimeout(timer); reject(error); });
      child.once("close", (code) => {
        clearTimeout(timer);
        if (code !== 0) return reject(new Error(`time authority fixture runner failed (${code}): ${stderr}`));
        try { resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
      });
    });
  } finally { await rm(directory, { recursive: true, force: true }); }
}

test("live time deadline survives a client that ignores SIGTERM without blocking the verifier", async () => {
  const result = await runFaultyAuthority('process.on("SIGTERM",()=>{});setTimeout(()=>process.exit(0),10000);');
  assert.match(result.message, /timed out/); assert.equal(result.ready, true); assert.equal(result.ticked, true); assert.ok(result.elapsed < FAULT_AUTHORITY_TIMEOUT_MS + 2000);
});

test("live time deadline closes pipes retained by a client descendant", async () => {
  const result = await runFaultyAuthority('import {spawn} from "node:child_process";spawn(process.execPath,["-e",\'process.on("SIGTERM",()=>{});setTimeout(()=>process.exit(0),10000)\'],{stdio:["ignore",process.stdout,process.stderr]});process.exit(0);');
  assert.match(result.message, /timed out/); assert.equal(result.ready, true); assert.equal(result.ticked, true); assert.ok(result.elapsed < FAULT_AUTHORITY_TIMEOUT_MS + 2000);
});

test("live time output bounds apply to stdout and stderr", async () => {
  for (const stream of ["stdout", "stderr"]) {
    const result = await runFaultyAuthority(`process.on("SIGTERM",()=>{});process.${stream}.write("x".repeat(65537));setTimeout(()=>process.exit(0),10000);`, 5000);
    assert.match(result.message, /response size is invalid/, JSON.stringify({ stream, ...result })); assert.ok(result.elapsed < 5000);
  }
});

test("live time client failure never exposes its stderr", async () => {
  const result = await runFaultyAuthority('process.stderr.write("private authority credential must stay private");process.exit(1);', 5000);
  assert.equal(result.message, "live time authority client rejected request");
});

test("malformed live time response never exposes confidential stdout in a parse error", async () => {
  const result = await runFaultyAuthority('process.stdout.write("CONFIDENTIAL_AUTHORITY_OUTPUT is not JSON");', 5000);
  assert.equal(result.message, "live time authority response is not valid JSON");
  assert.equal(result.message.includes("CONFIDENTIAL_AUTHORITY_OUTPUT"), false);
});
