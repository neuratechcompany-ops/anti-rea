import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
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
