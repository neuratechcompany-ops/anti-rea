import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { consumeEvidenceChallenge, createEvidenceChallengeEnvelope, verifyEvidenceChallenge } from "../scripts/evidence-challenge.mjs";

function fixture(overrides = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const issuedAt = new Date(Date.now() - 1000).toISOString();
  const payload = {
    schemaVersion: 1, challengeId: "1".repeat(64), product: "Fixture", evaluationId: "fixture-evaluation-1", policySha256: "2".repeat(64), artifactSha256: "3".repeat(64),
    kind: "analyzer-probe", workerKeyId: "4".repeat(64), runnerId: "isolated-runner", environmentSha256: "5".repeat(64),
    workloadIdentity: "spiffe://fixture.test/anti-rea/worker", issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(), ...overrides,
  };
  const bytes = Buffer.from(`${JSON.stringify(createEvidenceChallengeEnvelope(payload, privateKey), null, 2)}\n`);
  return { payload, bytes, publicKey };
}

test("verifies a short-lived challenge bound to policy, artifact, worker and workload", () => {
  const value = fixture();
  const verified = verifyEvidenceChallenge(value.bytes, value.publicKey, { product: value.payload.product, policySha256: value.payload.policySha256, artifactSha256: value.payload.artifactSha256, kind: value.payload.kind, workerKeyId: value.payload.workerKeyId });
  assert.equal(verified.payload.workloadIdentity, value.payload.workloadIdentity);
  assert.match(verified.envelopeSha256, /^[a-f0-9]{64}$/);
});

test("rejects challenge scope substitution", () => {
  const value = fixture();
  assert.throws(() => verifyEvidenceChallenge(value.bytes, value.publicKey, { policySha256: "f".repeat(64) }), /policySha256 mismatch/);
  assert.throws(() => verifyEvidenceChallenge(value.bytes, value.publicKey, { artifactSha256: "e".repeat(64) }), /artifactSha256 mismatch/);
});

test("rejects a challenge validity window longer than fifteen minutes", () => {
  const issuedAt = new Date(Date.now() - 1000).toISOString();
  assert.throws(() => fixture({ issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 16 * 60 * 1000).toISOString() }), /at most 15 minutes/);
});

test("atomically consumes a challenge only once across assessment processes", async () => {
  const value = fixture();
  const ledger = await mkdtemp(path.join(tmpdir(), "rea-challenge-ledger-"));
  const verified = verifyEvidenceChallenge(value.bytes, value.publicKey, { evaluationId: value.payload.evaluationId });
  const first = await consumeEvidenceChallenge(ledger, verified, value.payload.evaluationId);
  assert.match(first.sha256, /^[a-f0-9]{64}$/);
  await assert.rejects(() => consumeEvidenceChallenge(ledger, verified, value.payload.evaluationId), /already consumed/);
});
