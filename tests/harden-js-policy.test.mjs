import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const pipeline = path.join(root, "scripts", "harden-js.sh"); const policyTool = path.join(root, "scripts", "protection-policy.mjs");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const deliverySurfaces = [
  { id: "release-primary", kind: "release", audience: "customer", disposition: "present", rationale: "release" }, { id: "update-stable", kind: "update", audience: "customer", disposition: "present", rationale: "updates" },
  { id: "crash-none", kind: "crash", audience: "none", disposition: "not-applicable", rationale: "fixture has no crash upload" }, { id: "support-none", kind: "support", audience: "none", disposition: "not-applicable", rationale: "fixture has no support export" }, { id: "symbols-none", kind: "symbols", audience: "none", disposition: "not-applicable", rationale: "fixture has no symbols" },
];

async function fixture(profileSha256) {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-pipeline-policy-"));
  const input = path.join(directory, "input.js"); const canaries = path.join(directory, "canaries.json"); const exposure = path.join(directory, "exposure.json");
  await writeFile(input, "/* @anti-rea-vm */ function costOnly(x){return x+1}\n"); await writeFile(canaries, "[]\n"); await writeFile(exposure, "{}\n");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519"); const privatePath = path.join(directory, "private.pem"); const publicPath = path.join(directory, "public.pem");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" })); await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }));
  const now = Date.now(); const regressionTests = ["functional", "performance", "platform-security"].map((kind) => ({ kind, suiteId: `${kind}-suite`, suiteSha256: "1".repeat(64), runnerId: "runner", runnerExecutableSha256: "2".repeat(64), environmentSha256: "3".repeat(64) }));
  const payload = { schemaVersion: 6, deliverySurfaces, policyId: "pipeline-policy", product: "fixture", issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60 * 60 * 1000).toISOString(), exposurePolicySha256: "4".repeat(64), productSource: { repositoryUri: "https://example.invalid/fixture.git", commit: "5".repeat(40), tree: "6".repeat(40), buildDefinitionSha256: "7".repeat(64), builderId: "builder", builderKeyId: "8".repeat(64), builderEnvironmentSha256: "9".repeat(64) }, protectorDependencies: { packageLockSha256: "f".repeat(64), closureSha256: "e".repeat(64) }, protectionTransform: { surface: "javascript", backend: "selective-vm+javascript-obfuscator", virtualizerName: "anti-rea-selective-vm", virtualizerVersion: "1.2.0", keyMode: "external", encryption: "chacha20-poly1305", transformerName: "javascript-obfuscator", transformerVersion: "5.9.0", profileId: "javascript-vm-balanced", profileSha256, claimTier: "T1" }, serverAuthorization: { environment: "staging", channel: "stable", action: "license.activate", deploymentSha256: "0".repeat(64), configSha256: "1".repeat(64), transcriptSchemaSha256: "2".repeat(64) }, evidenceWorkerKeyIds: ["a".repeat(64)], regressionTests, analyzers: [{ family: "rea", adapterSha256: "b".repeat(64), executableSha256: "c".repeat(64) }, { family: "strings", adapterSha256: "d".repeat(64), executableSha256: "e".repeat(64) }], comparisons: [{ id: "FIXTURE-1", factIds: ["FACT-1"], tier: "T1", targetMax: 1, minimumImprovement: 1, requiredAnalyzerFamilies: ["rea", "strings"], requiredProbes: ["anti-rea-vm-runtime-hook"] }] };
  const unsigned = path.join(directory, "policy.json"); const signed = path.join(directory, "policy.signed.json"); await writeFile(unsigned, JSON.stringify(payload));
  const signedResult = spawnSync(process.execPath, [policyTool, "sign", "--policy", unsigned, "--private-key", privatePath, "--out", signed], { encoding: "utf8" }); assert.equal(signedResult.status, 0, signedResult.stderr);
  return { directory, input, canaries, exposure, signed, publicPath, out: `${directory}-out`, evidence: `${directory}-evidence` };
}

function invoke(value, env = {}) {
  return spawnSync("bash", [pipeline, value.input, value.out, value.evidence, value.canaries, value.exposure, value.signed, value.publicPath, "123", "456"], { encoding: "utf8", env: { ...process.env, ...env } });
}

test("owner policy overrides an attempted embedded environment downgrade", async () => {
  const profileSha256 = sha(await readFile(path.join(root, "profiles", "javascript-vm-balanced.json"))); const value = await fixture(profileSha256);
  const result = invoke(value, { ANTI_REA_VM_KEY_MODE: "embedded", ANTI_REA_VM_BUILD_KEY: "" });
  assert.equal(result.status, 64); assert.match(result.stderr, /external VM mode requires/);
});

test("pipeline refuses a profile whose installed digest differs from owner policy", async () => {
  const value = await fixture("f".repeat(64)); const result = invoke(value);
  assert.equal(result.status, 65); assert.match(result.stderr, /profile digest does not match/);
});
