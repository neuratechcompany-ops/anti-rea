import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const cli = path.join(root, "scripts", "protection-policy.mjs");
const sha = (value) => createHash("sha256").update(value).digest("hex");

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-policy-"));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, "private.pem"); const publicPath = path.join(directory, "public.pem");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }));
  await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }));
  const payload = {
    schemaVersion: 6,
    policyId: "owned-product-policy-1",
    product: "owned-product",
    issuedAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    exposurePolicySha256: sha(Buffer.from("exposure-policy")),
    productSource: { repositoryUri: "https://example.invalid/owned-product.git", commit: "b".repeat(40), tree: "c".repeat(40), buildDefinitionSha256: "d".repeat(64), builderId: "trusted-builder", builderKeyId: "e".repeat(64), builderEnvironmentSha256: "f".repeat(64) },
    protectorDependencies: { packageLockSha256: "a".repeat(64), closureSha256: "b".repeat(64) },
    protectionTransform: { surface: "javascript", backend: "selective-vm+javascript-obfuscator", virtualizerName: "anti-rea-selective-vm", virtualizerVersion: "1.2.0", keyMode: "external", encryption: "chacha20-poly1305", transformerName: "javascript-obfuscator", transformerVersion: "5.9.0", profileId: "javascript-vm-balanced", profileSha256: "0".repeat(64), claimTier: "T1" },
    serverAuthorization: { environment: "staging", channel: "stable", action: "license.activate", deploymentSha256: "b".repeat(64), configSha256: "c".repeat(64), transcriptSchemaSha256: "d".repeat(64) },
    deliverySurfaces: [
      { id: "release-primary", kind: "release", audience: "customer", disposition: "present", rationale: "customer release tree" },
      { id: "update-stable", kind: "update", audience: "customer", disposition: "present", rationale: "stable update tree" },
      { id: "crash-upload", kind: "crash", audience: "internal", disposition: "present", rationale: "crash ingestion staging tree" },
      { id: "support-export", kind: "support", audience: "internal", disposition: "present", rationale: "support export staging tree" },
      { id: "symbols-private", kind: "symbols", audience: "internal", disposition: "present", rationale: "private symbol tree" },
    ],
    evidenceWorkerKeyIds: ["5".repeat(64)],
    regressionTests: [
      { kind: "functional", suiteId: "functional-suite", suiteSha256: "6".repeat(64), runnerId: "trusted-runner", runnerExecutableSha256: "7".repeat(64), environmentSha256: "8".repeat(64) },
      { kind: "performance", suiteId: "performance-suite", suiteSha256: "9".repeat(64), runnerId: "trusted-runner", runnerExecutableSha256: "7".repeat(64), environmentSha256: "8".repeat(64) },
      { kind: "platform-security", suiteId: "platform-suite", suiteSha256: "a".repeat(64), runnerId: "trusted-runner", runnerExecutableSha256: "7".repeat(64), environmentSha256: "8".repeat(64) },
    ],
    analyzers: [
      { family: "rea", adapterSha256: "1".repeat(64), executableSha256: "2".repeat(64) },
      { family: "binary-strings", adapterSha256: "3".repeat(64), executableSha256: "4".repeat(64) },
    ],
    comparisons: [{
      id: "L-01", factIds: ["ALG-01"], tier: "T1", targetMax: 1, minimumImprovement: 1,
      requiredAnalyzerFamilies: ["rea", "binary-strings"],
      requiredProbes: ["anti-rea-vm-public-deobfuscator", "anti-rea-vm-runtime-hook"],
    }],
  };
  const unsigned = path.join(directory, "policy.json"); const signed = path.join(directory, "signed.json");
  await writeFile(unsigned, `${JSON.stringify(payload, null, 2)}\n`);
  return { directory, privatePath, publicPath, payload, unsigned, signed };
}

test("signs and verifies a precommitted protection policy", async () => {
  const current = await fixture();
  let result = spawnSync(process.execPath, [cli, "sign", "--policy", current.unsigned, "--private-key", current.privatePath, "--out", current.signed], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  result = spawnSync(process.execPath, [cli, "verify", "--policy", current.signed, "--public-key", current.publicPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).policyId, current.payload.policyId);
});

test("rejects an embedded-key downgrade under a T1 owner claim", async () => {
  const current = await fixture();
  current.payload.protectionTransform.keyMode = "embedded";
  current.payload.protectionTransform.encryption = "embedded-xorshift";
  await writeFile(current.unsigned, `${JSON.stringify(current.payload, null, 2)}\n`);
  const result = spawnSync(process.execPath, [cli, "sign", "--policy", current.unsigned, "--private-key", current.privatePath, "--out", current.signed], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /T1\+ claim requires external key mode/);
});

test("rejects tampering, an untrusted key, and post-result threshold weakening", async () => {
  const current = await fixture();
  let result = spawnSync(process.execPath, [cli, "sign", "--policy", current.unsigned, "--private-key", current.privatePath, "--out", current.signed], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const envelope = JSON.parse(await readFile(current.signed, "utf8"));
  const payload = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
  payload.comparisons[0].targetMax = 4;
  envelope.payload = Buffer.from(JSON.stringify(payload)).toString("base64");
  await writeFile(current.signed, `${JSON.stringify(envelope)}\n`);
  result = spawnSync(process.execPath, [cli, "verify", "--policy", current.signed, "--public-key", current.publicPath], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /signature is invalid/);

  const other = generateKeyPairSync("ed25519").publicKey;
  const otherPath = path.join(current.directory, "other.pem");
  await writeFile(otherPath, other.export({ type: "spki", format: "pem" }));
  result = spawnSync(process.execPath, [cli, "verify", "--policy", current.signed, "--public-key", otherPath], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /not trusted/);
});
