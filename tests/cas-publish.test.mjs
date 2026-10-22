import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createTrustBundleEnvelope } from "../scripts/trust-bundle.mjs";
import { createLiveTimeAuthorityClient } from "./helpers/live-time-authority.mjs";

const root = path.resolve(import.meta.dirname, "..");
const tool = path.join(root, "scripts", "cas-publish.mjs");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const keyId = (key) => sha((key.type === "public" ? key : createPublicKey(key)).export({ type: "spki", format: "der" }));
const trustEntry = (key) => { const publicKey = key.type === "public" ? key : createPublicKey(key); const der = publicKey.export({ type: "spki", format: "der" }); return { keyId: sha(der), publicKeySpkiBase64: der.toString("base64") }; };
function envelope(format, payload, privateKey) { const bytes = Buffer.from(JSON.stringify(payload)); return { format, keyId: keyId(privateKey), payload: bytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${format}\0`), bytes]), privateKey).toString("base64") }; }

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-cas-")); const artifact = path.join(directory, "artifact"); const casRoot = path.join(directory, "cas"); await mkdir(artifact);
  const appBytes = Buffer.from("protected-release"); await writeFile(path.join(artifact, "app.js"), appBytes);
  const releaseSigner = generateKeyPairSync("ed25519"); const manifestSigner = generateKeyPairSync("ed25519"); const publisher = generateKeyPairSync("ed25519"); const trustRoot = generateKeyPairSync("ed25519"); const timeAuthority = generateKeyPairSync("ed25519");
  const publisherPrivate = path.join(directory, "publisher-private.pem"); const trustRootPublic = path.join(directory, "trust-root-public.pem");
  await writeFile(publisherPrivate, publisher.privateKey.export({ type: "pkcs8", format: "pem" })); await writeFile(trustRootPublic, trustRoot.publicKey.export({ type: "spki", format: "pem" }));
  const issuedAt = new Date(Date.now() - 1000).toISOString(); const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const trustPayload = { schemaVersion: 1, bundleId: "cas-fixture-roots", product: "CASProduct", environment: "production", issuedAt, expiresAt, roles: { "artifact-publisher": [trustEntry(publisher.publicKey)], "release-attestation": [trustEntry(releaseSigner.publicKey)], "release-manifest": [trustEntry(manifestSigner.publicKey)], "time-authority": [trustEntry(timeAuthority.publicKey)] } };
  const trustBundle = path.join(directory, "trust-bundle.json"); const trustBundleBytes = Buffer.from(JSON.stringify(createTrustBundleEnvelope(trustPayload, trustRoot.privateKey))); await writeFile(trustBundle, trustBundleBytes);
  const timeLedger = path.join(directory, "time-ledger"); await mkdir(timeLedger); const timeAuthorityClient = await createLiveTimeAuthorityClient(directory, timeAuthority.privateKey);
  return { directory, artifact, casRoot, appBytes, releaseSigner, manifestSigner, publisherPrivate, trustRootPublic, trustBundle, trustBundleBytes, timeAuthority, timeAuthorityClient, timeLedger, trustEnvironment: trustPayload.environment };
}

async function releaseFiles(value, release, sequence = 1, previous = null) {
  const files = [{ path: "app.js", bytes: value.appBytes.length, sha256: sha(value.appBytes) }];
  const artifactSha256 = sha(Buffer.from(files.map((file) => `${file.path}\0${file.bytes}\0${file.sha256}`).join("\n")));
  const manifestPayload = { schemaVersion: 1, product: "CASProduct", release, files }; const manifestBytes = Buffer.from(`${JSON.stringify(envelope("rea-hardening-release/v1", manifestPayload, value.manifestSigner.privateKey), null, 2)}\n`); const manifest = path.join(value.directory, `manifest-${release}.json`); await writeFile(manifest, manifestBytes);
  const bindings = { artifactReportSha256: "1".repeat(64), assessmentResultSha256: "2".repeat(64), assessmentGateKeyId: "3".repeat(64), exposureReportSha256: "4".repeat(64), virtualizationReportSha256: "5".repeat(64), transformReportSha256: "6".repeat(64), provenanceSha256: "7".repeat(64), releaseManifestSha256: sha(manifestBytes), releaseManifestKeyId: keyId(value.manifestSigner.publicKey), protectionPolicySha256: "8".repeat(64), productBuildAttestationSha256: "9".repeat(64), tripwireManifestSha256: "a".repeat(64), trustBundleSha256: sha(value.trustBundleBytes) };
  const issuedAt = new Date().toISOString(); const attestationPayload = { schemaVersion: 1, product: "CASProduct", channel: "stable", release, sequence, issuedAt, expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), clock: { source: "signed-live", observedAt: issuedAt, keyId: "b".repeat(64), attestationSha256: "c".repeat(64), consumptionSha256: "d".repeat(64), nonce: "e".repeat(64), requestSha256: "f".repeat(64), verifierRunId: "1".repeat(64) }, artifactSha256, bindings, previous };
  const attestation = path.join(value.directory, `attestation-${release}.json`); await writeFile(attestation, `${JSON.stringify(envelope("rea-hardening-release-attestation/v13", attestationPayload, value.releaseSigner.privateKey), null, 2)}\n`);
  return { manifest, attestation, artifactSha256 };
}
function publish(value, releaseValue) {
  return spawnSync(process.execPath, [tool, "--artifact", value.artifact, "--cas-root", value.casRoot, "--release-manifest", releaseValue.manifest, "--release-attestation", releaseValue.attestation, "--trust-bundle", value.trustBundle, "--trust-root-public-key", value.trustRootPublic, "--time-authority-client", value.timeAuthorityClient, "--time-ledger", value.timeLedger, "--publisher-private-key", value.publisherPrivate, "--product", "CASProduct", "--channel", "stable", "--release", path.basename(releaseValue.manifest).slice("manifest-".length, -".json".length), "--minimum-sequence", "1"], { encoding: "utf8" });
}

test("publishes an attested artifact into a read-only content-addressed object and is idempotent", async () => {
  const value = await fixture(); const releaseValue = await releaseFiles(value, "1.0.0"); const first = publish(value, releaseValue); assert.equal(first.status, 0, first.stderr);
  const result = JSON.parse(first.stdout); assert.equal(result.status, "published"); assert.equal(result.artifactSha256, releaseValue.artifactSha256);
  const staged = path.join(value.casRoot, result.object, "payload", "app.js"); assert.equal(await readFile(staged, "utf8"), "protected-release"); assert.equal((await stat(staged)).mode & 0o222, 0);
  const second = publish(value, releaseValue); assert.equal(second.status, 0, second.stderr); assert.equal(JSON.parse(second.stdout).status, "already-published");
});

test("rejects a mutable artifact changed after release attestation", async () => {
  const value = await fixture(); const releaseValue = await releaseFiles(value, "1.0.0"); await writeFile(path.join(value.artifact, "app.js"), "tampered");
  const result = publish(value, releaseValue); assert.equal(result.status, 1); assert.match(result.stderr, /does not match the attested release inventory/);
});

test("rejects a second genesis branch for an existing product channel", async () => {
  const value = await fixture(); const firstRelease = await releaseFiles(value, "1.0.0"); assert.equal(publish(value, firstRelease).status, 0);
  const fork = await releaseFiles(value, "2.0.0"); const result = publish(value, fork); assert.equal(result.status, 1); assert.match(result.stderr, /genesis fork rejected/);
});

test("advances only from the exact publisher head and rejects a forged predecessor", async () => {
  const value = await fixture(); const first = await releaseFiles(value, "1.0.0"); assert.equal(publish(value, first).status, 0);
  const firstAttestationSha256 = sha(await readFile(first.attestation));
  const second = await releaseFiles(value, "1.0.1", 2, { sequence: 1, attestationSha256: firstAttestationSha256 });
  const advanced = publish(value, second); assert.equal(advanced.status, 0, advanced.stderr); assert.equal(JSON.parse(advanced.stdout).sequence, 2);
  const forged = await releaseFiles(value, "1.0.2", 3, { sequence: 2, attestationSha256: "f".repeat(64) });
  const rejected = publish(value, forged); assert.equal(rejected.status, 1); assert.match(rejected.stderr, /predecessor does not match/);
});
