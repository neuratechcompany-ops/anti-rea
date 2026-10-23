import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { RELEASE_ATTESTATION_FORMAT, verifyReleaseAttestationEnvelope } from "../scripts/release-attestation.mjs";
import { createTrustBundleEnvelope, verifyTrustBundleEnvelope } from "../scripts/trust-bundle.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");

function fixture() {
  const root = generateKeyPairSync("ed25519");
  const signer = generateKeyPairSync("ed25519");
  const publicDer = signer.publicKey.export({ type: "spki", format: "der" });
  const keyId = hash(publicDer);
  const milliseconds = Date.parse("2030-01-01T00:00:00.000Z");
  const observedAt = new Date(milliseconds).toISOString();
  const trustBytes = Buffer.from(JSON.stringify(createTrustBundleEnvelope({
    schemaVersion: 1, bundleId: "release-envelope-tests", product: "Example",
    environment: "production", issuedAt: observedAt, expiresAt: "2030-02-01T00:00:00.000Z",
    roles: { "release-attestation": [{ keyId, publicKeySpkiBase64: publicDer.toString("base64") }] },
  }, root.privateKey, milliseconds)));
  const bundle = verifyTrustBundleEnvelope(trustBytes, root.publicKey.export({ type: "spki", format: "pem" }), { product: "Example", now: observedAt });
  const bindingNames = ["artifactReportSha256", "assessmentResultSha256", "assessmentGateKeyId", "exposureReportSha256", "virtualizationReportSha256", "transformReportSha256", "provenanceSha256", "releaseManifestSha256", "releaseManifestKeyId", "protectionPolicySha256", "productBuildAttestationSha256", "tripwireManifestSha256", "trustBundleSha256"];
  const payload = {
    schemaVersion: 1, product: "Example", channel: "stable", release: "1.0.1", sequence: 2,
    issuedAt: observedAt, expiresAt: "2030-01-02T00:00:00.000Z",
    clock: { source: "signed-live", observedAt, ...Object.fromEntries(["keyId", "attestationSha256", "consumptionSha256", "nonce", "requestSha256", "verifierRunId"].map((name) => [name, "1".repeat(64)])) },
    artifactSha256: "2".repeat(64), bindings: Object.fromEntries(bindingNames.map((name) => [name, "3".repeat(64)])),
    previous: { sequence: 1, attestationSha256: "4".repeat(64) },
  };
  function verify(value) {
    const bytes = Buffer.from(JSON.stringify(value));
    const envelope = Buffer.from(JSON.stringify({ format: RELEASE_ATTESTATION_FORMAT, keyId, payload: bytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${RELEASE_ATTESTATION_FORMAT}\0`), bytes]), signer.privateKey).toString("base64") }));
    return verifyReleaseAttestationEnvelope(envelope, bundle, { product: "Example", channel: "stable", release: "1.0.1", clock: { source: "signed-live", observedAt, milliseconds } });
  }
  return { payload, verify };
}

test("release envelope verifier accepts genesis and immediate predecessor links", () => {
  const { payload, verify } = fixture();
  assert.equal(verify(payload).payload.sequence, 2);
  assert.equal(verify({ ...payload, sequence: 1, previous: null }).payload.sequence, 1);
});

test("release envelope verifier rejects signed skipped, self and future predecessors", () => {
  const { payload, verify } = fixture();
  for (const sequence of [1, 3, 4]) {
    assert.throws(() => verify({ ...payload, sequence: 3, previous: { ...payload.previous, sequence } }), /previous attestation binding/);
  }
  assert.throws(() => verify({ ...payload, previous: { ...payload.previous, ignored: true } }), /previous attestation binding/);
});

test("release envelope verifier enforces the signer's bounded validity window", () => {
  const { payload, verify } = fixture();
  assert.throws(() => verify({ ...payload, expiresAt: "2032-01-01T00:00:00.000Z" }), /validity window/);
  assert.throws(() => verify({ ...payload, issuedAt: "2030-01-01T00:01:00.000Z", expiresAt: "2030-01-01T00:00:30.000Z", clock: { ...payload.clock, observedAt: "2030-01-01T00:01:00.000Z" } }), /validity window/);
});
