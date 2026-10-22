import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createEvidenceChallengeEnvelope } from "../scripts/evidence-challenge.mjs";
import { createTrustBundleEnvelope } from "../scripts/trust-bundle.mjs";

const cli = path.resolve(import.meta.dirname, "..", "scripts", "server-authorization.mjs");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const identity = (key) => { const der = key.export({ type: "spki", format: "der" }); return { keyId: sha(der), publicKeySpkiBase64: der.toString("base64") }; };
const deliverySurfaces = [
  { id: "release-primary", kind: "release", audience: "customer", disposition: "present", rationale: "release" }, { id: "update-stable", kind: "update", audience: "customer", disposition: "present", rationale: "updates" },
  { id: "crash-none", kind: "crash", audience: "none", disposition: "not-applicable", rationale: "fixture has no crash upload" }, { id: "support-none", kind: "support", audience: "none", disposition: "not-applicable", rationale: "fixture has no support export" }, { id: "symbols-none", kind: "symbols", audience: "none", disposition: "not-applicable", rationale: "fixture has no symbols" },
];

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-server-auth-")); const now = Date.now();
  const root = generateKeyPairSync("ed25519"), policyKey = generateKeyPairSync("ed25519"), coordinator = generateKeyPairSync("ed25519"), server = generateKeyPairSync("ed25519");
  const rootPublic = path.join(directory, "root.pem"), serverPrivate = path.join(directory, "server.pem");
  await writeFile(rootPublic, root.publicKey.export({ type: "spki", format: "pem" })); await writeFile(serverPrivate, server.privateKey.export({ type: "pkcs8", format: "pem" }));
  const issuedAt = new Date(now - 1000).toISOString(), expiresAt = new Date(now + 60 * 60 * 1000).toISOString();
  const schema = path.join(directory, "transcript-schema.json"); const schemaBytes = Buffer.from('{"schemaVersion":1}\n'); await writeFile(schema, schemaBytes);
  const serverAuthorization = { environment: "production-like", channel: "stable", action: "license.activate", deploymentSha256: "1".repeat(64), configSha256: "2".repeat(64), transcriptSchemaSha256: sha(schemaBytes) };
  const regressionTests = ["functional", "performance", "platform-security"].map((kind) => ({ kind, suiteId: `${kind}-suite`, suiteSha256: "3".repeat(64), runnerId: "runner", runnerExecutableSha256: "4".repeat(64), environmentSha256: "5".repeat(64) }));
  const policyPayload = { schemaVersion: 6, deliverySurfaces, policyId: "server-auth-policy", product: "Example", issuedAt, expiresAt, exposurePolicySha256: "6".repeat(64), productSource: { repositoryUri: "https://example.invalid/product.git", commit: "7".repeat(40), tree: "8".repeat(40), buildDefinitionSha256: "9".repeat(64), builderId: "builder", builderKeyId: "a".repeat(64), builderEnvironmentSha256: "b".repeat(64) }, protectorDependencies: { packageLockSha256: "2".repeat(64), closureSha256: "3".repeat(64) }, protectionTransform: { surface: "javascript", backend: "selective-vm+javascript-obfuscator", virtualizerName: "anti-rea-selective-vm", virtualizerVersion: "1.2.0", keyMode: "external", encryption: "chacha20-poly1305", transformerName: "javascript-obfuscator", transformerVersion: "5.9.0", profileId: "javascript-vm-balanced", profileSha256: "c".repeat(64), claimTier: "T1" }, serverAuthorization, evidenceWorkerKeyIds: ["d".repeat(64)], regressionTests, analyzers: [{ family: "rea", adapterSha256: "e".repeat(64), executableSha256: "f".repeat(64) }, { family: "strings", adapterSha256: "0".repeat(64), executableSha256: "1".repeat(64) }], comparisons: [{ id: "L-01", factIds: ["ALG-01"], tier: "T1", targetMax: 1, minimumImprovement: 1, requiredAnalyzerFamilies: ["rea", "strings"], requiredProbes: ["anti-rea-vm-runtime-hook"] }] };
  const policyPayloadBytes = Buffer.from(JSON.stringify(policyPayload)); const policy = path.join(directory, "policy.json");
  const policyEnvelope = { format: "rea-hardening-protection-policy/v6", keyId: identity(policyKey.publicKey).keyId, payload: policyPayloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from("rea-hardening-protection-policy/v6\0"), policyPayloadBytes]), policyKey.privateKey).toString("base64") };
  const policyBytes = Buffer.from(`${JSON.stringify(policyEnvelope)}\n`); await writeFile(policy, policyBytes);
  const trust = path.join(directory, "trust.json"); const trustPayload = { schemaVersion: 1, bundleId: "production", product: "Example", environment: "production-like", issuedAt, expiresAt, roles: { "protection-policy": [identity(policyKey.publicKey)], "evidence-coordinator": [identity(coordinator.publicKey)], "server-authorization": [identity(server.publicKey)] } };
  await writeFile(trust, `${JSON.stringify(createTrustBundleEnvelope(trustPayload, root.privateKey))}\n`);
  const challenge = path.join(directory, "challenge.json"); const challengePayload = { schemaVersion: 1, challengeId: "2".repeat(64), product: "Example", evaluationId: "release-evaluation-1", policySha256: sha(policyBytes), artifactSha256: "3".repeat(64), kind: "server-authorization", workerKeyId: identity(server.publicKey).keyId, runnerId: "server-test-runner", environmentSha256: serverAuthorization.deploymentSha256, workloadIdentity: "spiffe://example.test/server-auth", issuedAt, expiresAt: new Date(now + 10 * 60 * 1000).toISOString() };
  await writeFile(challenge, `${JSON.stringify(createEvidenceChallengeEnvelope(challengePayload, coordinator.privateKey))}\n`);
  const transcript = path.join(directory, "transcript.json"); const transcriptValue = { schemaVersion: 1, product: "Example", ...serverAuthorization, transcriptSchemaSha256: undefined, scenarios: [{ name: "legitimate-client", mutation: "none", requestSha256: "4".repeat(64), responseSha256: "5".repeat(64), clientDecision: "allowed", serverDecision: "allowed", httpStatus: 200 }, { name: "patched-favorable-client", mutation: "forced local allow", requestSha256: "6".repeat(64), responseSha256: "7".repeat(64), clientDecision: "allowed", serverDecision: "denied", httpStatus: 403 }] };
  delete transcriptValue.transcriptSchemaSha256; await writeFile(transcript, `${JSON.stringify(transcriptValue)}\n`);
  return { directory, rootPublic, serverPrivate, policy, trust, challenge, transcript, schema };
}

function invoke(value, output) { return spawnSync(process.execPath, [cli, "sign", "--transcript", value.transcript, "--transcript-schema", value.schema, "--protection-policy", value.policy, "--trust-bundle", value.trust, "--trust-root-public-key", value.rootPublic, "--challenge", value.challenge, "--private-key", value.serverPrivate, "--expires-at", new Date(Date.now() + 30 * 60 * 1000).toISOString(), "--out", output], { encoding: "utf8" }); }

test("signs only an owner-precommitted server authorization transcript and challenge", async () => {
  const value = await fixture(); const output = path.join(value.directory, "receipt.json"); const result = invoke(value, output);
  assert.equal(result.status, 0, result.stderr); const envelope = JSON.parse(await readFile(output, "utf8")); const payload = JSON.parse(Buffer.from(envelope.payload, "base64"));
  assert.equal(payload.action, "license.activate"); assert.equal(payload.challengeId, "2".repeat(64)); assert.match(payload.transcriptSha256, /^[a-f0-9]{64}$/);
});

test("refuses a harmless substitute action before signing", async () => {
  const value = await fixture(); const transcript = JSON.parse(await readFile(value.transcript, "utf8")); transcript.action = "health.check"; await writeFile(value.transcript, `${JSON.stringify(transcript)}\n`);
  const result = invoke(value, path.join(value.directory, "receipt.json")); assert.equal(result.status, 1); assert.match(result.stderr, /action differs from owner policy/);
});
