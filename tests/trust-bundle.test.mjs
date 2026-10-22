import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { createTrustBundleEnvelope, trustedRoleKey, verifyTrustBundleEnvelope, verifyTrustBundleEnvelopeSignature } from "../scripts/trust-bundle.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
function identity(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  return { keyId: sha256(der), publicKeySpkiBase64: der.toString("base64") };
}
function fixture() {
  const root = generateKeyPairSync("ed25519");
  const policy = generateKeyPairSync("ed25519");
  const worker = generateKeyPairSync("ed25519");
  const server = generateKeyPairSync("ed25519");
  const now = Date.parse("2030-01-01T00:00:00.000Z");
  const payload = {
    schemaVersion: 1,
    bundleId: "production-roots-7",
    product: "FixtureProduct",
    environment: "production",
    issuedAt: "2029-12-31T23:55:00.000Z",
    expiresAt: "2030-06-01T00:00:00.000Z",
    roles: {
      "protection-policy": [identity(policy.publicKey)],
      "evidence-worker": [identity(worker.publicKey)],
      "server-authorization": [identity(server.publicKey)],
    },
  };
  return { root, policy, worker, server, now, payload };
}

test("verifies a root-signed role bundle and resolves only the requested role", () => {
  const value = fixture();
  const envelope = createTrustBundleEnvelope(value.payload, value.root.privateKey, value.now);
  const bytes = Buffer.from(`${JSON.stringify(envelope)}\n`);
  const verified = verifyTrustBundleEnvelope(bytes, value.root.publicKey, { product: "FixtureProduct", now: new Date(value.now).toISOString() });
  const worker = trustedRoleKey(verified, "evidence-worker", value.payload.roles["evidence-worker"][0].keyId);
  assert.equal(worker.keyId, value.payload.roles["evidence-worker"][0].keyId);
  assert.equal(worker.bytes.toString("utf8"), value.worker.publicKey.export({ type: "spki", format: "pem" }).toString("utf8"));
  assert.throws(() => trustedRoleKey(verified, "assessment-gate"), /lacks required role/);
});

test("rejects a substituted trust root and a modified role inventory", () => {
  const value = fixture(); const other = generateKeyPairSync("ed25519");
  const envelope = createTrustBundleEnvelope(value.payload, value.root.privateKey, value.now);
  const bytes = Buffer.from(JSON.stringify(envelope));
  assert.throws(() => verifyTrustBundleEnvelope(bytes, other.publicKey, { now: new Date(value.now).toISOString() }), /root key is not pinned/);
  const tampered = structuredClone(envelope);
  const payload = JSON.parse(Buffer.from(tampered.payload, "base64").toString("utf8"));
  payload.environment = "attacker-controlled";
  tampered.payload = Buffer.from(JSON.stringify(payload)).toString("base64");
  assert.throws(() => verifyTrustBundleEnvelope(Buffer.from(JSON.stringify(tampered)), value.root.publicKey, { now: new Date(value.now).toISOString() }), /signature is invalid/);
});

test("rejects one key reused across independent trust roles", () => {
  const value = fixture();
  value.payload.roles["server-authorization"] = [value.payload.roles["evidence-worker"][0]];
  assert.throws(() => createTrustBundleEnvelope(value.payload, value.root.privateKey, value.now), /reused across roles/);
});

test("can bootstrap role keys from a valid root signature before trusted time is known", () => {
  const value = fixture(); const envelope = createTrustBundleEnvelope(value.payload, value.root.privateKey, value.now); const bytes = Buffer.from(JSON.stringify(envelope));
  const bootstrapped = verifyTrustBundleEnvelopeSignature(bytes, value.root.publicKey, { product: value.payload.product }); assert.equal(bootstrapped.payload.bundleId, value.payload.bundleId);
  assert.throws(() => verifyTrustBundleEnvelope(bytes, value.root.publicKey, { now: "2040-01-01T00:00:00.000Z" }), /expired/);
});
