import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { verifyEvidenceAttestation } from "../scripts/evidence-attestation.mjs";
import { createEvidenceChallengeEnvelope } from "../scripts/evidence-challenge.mjs";

const root = path.resolve(import.meta.dirname, "..");
const cli = path.join(root, "scripts", "evidence-attestation.mjs");
const sha = (value) => createHash("sha256").update(value).digest("hex");

async function challenge(directory, coordinatorPrivate, workerPublic, artifactSha256, kind, expiresAt, name) {
  const coordinatorPublic = (await import("node:crypto")).createPublicKey(coordinatorPrivate);
  const publicPath = path.join(directory, `${name}-coordinator-public.pem`); const challengePath = path.join(directory, `${name}-challenge.json`);
  await writeFile(publicPath, coordinatorPublic.export({ type: "spki", format: "pem" }));
  const payload = { schemaVersion: 1, challengeId: sha(Buffer.from(`${name}-challenge`)), product: "owned-product", evaluationId: "fixture-evaluation-1", policySha256: "c".repeat(64), artifactSha256, kind, workerKeyId: sha(workerPublic.export({ type: "spki", format: "der" })), runnerId: "isolated-runner", environmentSha256: "d".repeat(64), workloadIdentity: "spiffe://example.test/anti-rea/worker", issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt };
  await writeFile(challengePath, `${JSON.stringify(createEvidenceChallengeEnvelope(payload, coordinatorPrivate), null, 2)}\n`);
  return { challengePath, publicPath, payload };
}

test("worker signs the exact report and artifact identity", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-worker-attestation-"));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const { privateKey: coordinatorPrivate } = generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, "private.pem"); const publicPath = path.join(directory, "public.pem");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }));
  await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }));
  const artifactSha256 = "a".repeat(64);
  const reportPath = path.join(directory, "probe.json"); const attestationPath = path.join(directory, "attestation.json");
  const reportBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, artifactIdentity: { kind: "file", sha256: artifactSha256 } }));
  await writeFile(reportPath, reportBytes);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const runChallenge = await challenge(directory, coordinatorPrivate, publicKey, artifactSha256, "analyzer-probe", expiresAt, "analyzer");
  const result = spawnSync(process.execPath, [cli, "sign", "--report", reportPath, "--kind", "analyzer-probe", "--challenge", runChallenge.challengePath, "--coordinator-public-key", runChallenge.publicPath, "--private-key", privatePath, "--run-id", "owned-worker-run-1", "--expires-at", expiresAt, "--out", attestationPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const verified = verifyEvidenceAttestation(await readFile(attestationPath), await readFile(publicPath), { kind: "analyzer-probe", reportSha256: sha(reportBytes), artifactSha256 });
  assert.equal(verified.payload.runId, "owned-worker-run-1");
  assert.equal(verified.payload.challengeId, runChallenge.payload.challengeId);
  assert.match(verified.keyId, /^[a-f0-9]{64}$/);
});

test("worker attestation rejects a substituted handwritten report", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-worker-forgery-"));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const { privateKey: coordinatorPrivate } = generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, "private.pem");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }));
  const artifactSha256 = "b".repeat(64);
  const reportPath = path.join(directory, "probe.json"); const attestationPath = path.join(directory, "attestation.json");
  const original = Buffer.from(JSON.stringify({ schemaVersion: 1, artifact: { path: "/owned/artifact", sha256: artifactSha256 }, status: "not-recovered" }));
  await writeFile(reportPath, original);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const runChallenge = await challenge(directory, coordinatorPrivate, publicKey, artifactSha256, "adversarial-probe", expiresAt, "adversarial");
  const result = spawnSync(process.execPath, [cli, "sign", "--report", reportPath, "--kind", "adversarial-probe", "--challenge", runChallenge.challengePath, "--coordinator-public-key", runChallenge.publicPath, "--private-key", privatePath, "--run-id", "owned-worker-run-2", "--expires-at", expiresAt, "--out", attestationPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const forged = Buffer.from(JSON.stringify({ schemaVersion: 1, artifact: { path: "/owned/artifact", sha256: artifactSha256 }, status: "recovered" }));
  const attestationBytes = await readFile(attestationPath);
  assert.throws(() => verifyEvidenceAttestation(attestationBytes, publicKey.export({ type: "spki", format: "pem" }), { kind: "adversarial-probe", reportSha256: sha(forged), artifactSha256 }), /reportSha256 mismatch/);
});
