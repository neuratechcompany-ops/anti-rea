import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createTrustBundleEnvelope } from "../scripts/trust-bundle.mjs";
import { inspectDependencyClosure } from "../scripts/dependency-closure.mjs";
import { createLiveTimeAuthorityClient } from "./helpers/live-time-authority.mjs";

const root = path.resolve(import.meta.dirname, "..");
const creator = path.join(root, "scripts", "create-provenance.mjs");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const keyId = (key) => sha((key.type === "public" ? key : createPublicKey(key)).export({ type: "spki", format: "der" }));
const trustEntry = (key) => { const publicKey = key.type === "public" ? key : createPublicKey(key); const der = publicKey.export({ type: "spki", format: "der" }); return { keyId: sha(der), publicKeySpkiBase64: der.toString("base64") }; };
const deliverySurfaces = [
  { id: "release-primary", kind: "release", audience: "customer", disposition: "present", rationale: "release" }, { id: "update-stable", kind: "update", audience: "customer", disposition: "present", rationale: "updates" },
  { id: "crash-none", kind: "crash", audience: "none", disposition: "not-applicable", rationale: "fixture has no crash upload" }, { id: "support-none", kind: "support", audience: "none", disposition: "not-applicable", rationale: "fixture has no support export" }, { id: "symbols-none", kind: "symbols", audience: "none", disposition: "not-applicable", rationale: "fixture has no symbols" },
];
function git(cwd, args) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
}
function envelope(format, payload, privateKey) {
  const bytes = Buffer.from(JSON.stringify(payload));
  return { format, keyId: keyId(privateKey), payload: bytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${format}\0`), bytes]), privateKey).toString("base64") };
}

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-provenance-"));
  const productRoot = `${directory}-product`; await mkdir(productRoot);
  await writeFile(path.join(productRoot, "build.mjs"), "export const build = true;\n");
  git(productRoot, ["init"]); git(productRoot, ["config", "user.email", "test@example.invalid"]); git(productRoot, ["config", "user.name", "Test"]);
  git(productRoot, ["remote", "add", "origin", "https://example.invalid/product.git"]); git(productRoot, ["add", "."]); git(productRoot, ["commit", "-m", "product"]);
  const productCommit = git(productRoot, ["rev-parse", "HEAD"]); const productTree = git(productRoot, ["rev-parse", "HEAD^{tree}"]);

  for (const name of ["adapters", "attacks", "profiles", "references", "scripts", "tests"]) {
    await mkdir(path.join(directory, name)); await writeFile(path.join(directory, name, "fixture.txt"), name);
  }
  await writeFile(path.join(directory, "package.json"), JSON.stringify({ name: "fixture-protector", version: "9.9.9" })); await writeFile(path.join(directory, "package-lock.json"), JSON.stringify({ name: "fixture-protector", version: "9.9.9", lockfileVersion: 3, packages: { "": { name: "fixture-protector", version: "9.9.9" } } })); await mkdir(path.join(directory, "node_modules")); await writeFile(path.join(directory, "SKILL.md"), "fixture skill\n");
  const artifactSha256 = "a".repeat(64); const artifactDirectory = path.join(directory, "release"); await mkdir(artifactDirectory);
  const virtualized = path.join(directory, "virtualized.js"); const transformed = path.join(artifactDirectory, "app.js"); await writeFile(virtualized, "virtualized"); await writeFile(transformed, "transformed");
  const artifactReport = path.join(directory, "artifact.json"); const assessment = path.join(directory, "assessment-result.json"); const exposure = path.join(directory, "exposure.json"); const virtualization = path.join(directory, "virtualization.json"); const transform = path.join(directory, "transform.json");
  await writeFile(artifactReport, JSON.stringify({ schemaVersion: 1, status: "passed", artifactSha256, artifact: artifactDirectory })); await writeFile(exposure, JSON.stringify({ schemaVersion: 1, status: "PASS", artifactVerification: { artifactSha256 } }));
  const inputSha256 = sha(Buffer.from("virtualized")); const canaries = ["b".repeat(64)];
  await writeFile(virtualization, JSON.stringify({ schemaVersion: 1, transformer: { name: "anti-rea-selective-vm", version: "1.2.0" }, key: { mode: "external", provider: "function-v1", encryption: "chacha20-poly1305" }, input: { path: virtualized, sha256: inputSha256 }, output: { path: virtualized, sha256: inputSha256 }, functions: [{ id: "f".repeat(64), name: "fixture" }], canaries: { sha256: canaries } }));
  const virtualizationSha256 = sha(await readFile(virtualization)); await writeFile(transform, JSON.stringify({ schemaVersion: 1, transformer: { name: "javascript-obfuscator", version: "5.9.0" }, profile: { id: "javascript-vm-balanced", sha256: "0".repeat(64) }, upstream: { virtualization: { sha256: virtualizationSha256, canarySha256: canaries } }, input: { sha256: inputSha256 }, output: { path: transformed, sha256: sha(Buffer.from("transformed")) } }));

  const { privateKey: builderPrivate, publicKey: builderPublic } = generateKeyPairSync("ed25519"); const builderPublicPath = path.join(directory, "builder-public.pem"); await writeFile(builderPublicPath, builderPublic.export({ type: "spki", format: "pem" }));
  const environmentSha256 = "1".repeat(64); const buildDefinition = path.join(productRoot, "build.mjs"); const buildDefinitionSha256 = sha(await readFile(buildDefinition)); const issuedAt = new Date().toISOString(); const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const buildPayload = { schemaVersion: 1, product: "Example", repositoryUri: "https://example.invalid/product.git", commit: productCommit, tree: productTree, buildDefinitionPath: "build.mjs", buildDefinitionSha256, virtualizationInputSha256: inputSha256, builderId: "fixture-builder", builderEnvironmentSha256: environmentSha256, runId: "fixture-run", issuedAt, expiresAt };
  const buildAttestation = path.join(directory, "product-build.json"); await writeFile(buildAttestation, JSON.stringify(envelope("rea-hardening-product-build-attestation/v1", buildPayload, builderPrivate)));

  const { privateKey: policyPrivate, publicKey: policyPublic } = generateKeyPairSync("ed25519"); const policyPublicPath = path.join(directory, "policy-public.pem"); await writeFile(policyPublicPath, policyPublic.export({ type: "spki", format: "pem" }));
  const regressionTests = ["functional", "performance", "platform-security"].map((kind) => ({ kind, suiteId: `${kind}-suite`, suiteSha256: "2".repeat(64), runnerId: "fixture-runner", runnerExecutableSha256: "3".repeat(64), environmentSha256: "4".repeat(64) }));
  const dependencyClosure = await inspectDependencyClosure(directory); const protectorDependencies = { packageLockSha256: dependencyClosure.packageLockSha256, closureSha256: dependencyClosure.closureSha256 };
  const protectionTransform = { surface: "javascript", backend: "selective-vm+javascript-obfuscator", virtualizerName: "anti-rea-selective-vm", virtualizerVersion: "1.2.0", keyMode: "external", encryption: "chacha20-poly1305", transformerName: "javascript-obfuscator", transformerVersion: "5.9.0", profileId: "javascript-vm-balanced", profileSha256: "0".repeat(64), claimTier: "T1" };
  const policyPayload = { schemaVersion: 6, deliverySurfaces, policyId: "fixture", product: "Example", exposurePolicySha256: "e".repeat(64), productSource: { repositoryUri: "https://example.invalid/product.git", commit: productCommit, tree: productTree, buildDefinitionSha256, builderId: "fixture-builder", builderKeyId: keyId(builderPublic), builderEnvironmentSha256: environmentSha256 }, protectorDependencies, protectionTransform, serverAuthorization: { environment: "production-like", channel: "stable", action: "license.activate", deploymentSha256: "a".repeat(64), configSha256: "b".repeat(64), transcriptSchemaSha256: "c".repeat(64) }, evidenceWorkerKeyIds: ["5".repeat(64)], analyzers: [{ family: "static-a", executableSha256: "6".repeat(64), adapterSha256: "7".repeat(64) }, { family: "static-b", executableSha256: "8".repeat(64), adapterSha256: "9".repeat(64) }], regressionTests, comparisons: [{ id: "FIXTURE-1", tier: "T1", targetMax: 1, minimumImprovement: 1, factIds: ["FACT-1"], requiredAnalyzerFamilies: ["static-a", "static-b"], requiredProbes: ["anti-rea-vm-runtime-hook"] }], issuedAt, expiresAt };
  const protectionPolicy = path.join(directory, "protection-policy.json"); const policyBytes = Buffer.from(`${JSON.stringify(envelope("rea-hardening-protection-policy/v6", policyPayload, policyPrivate))}\n`); await writeFile(protectionPolicy, policyBytes);

  const { privateKey: gatePrivateKey, publicKey: gatePublicKey } = generateKeyPairSync("ed25519"); const gatePublic = path.join(directory, "gate-public.pem"); await writeFile(gatePublic, gatePublicKey.export({ type: "spki", format: "pem" }));
  const { privateKey: timeAuthorityPrivateKey, publicKey: timeAuthorityPublicKey } = generateKeyPairSync("ed25519");
  const { privateKey: trustRootPrivateKey, publicKey: trustRootPublicKey } = generateKeyPairSync("ed25519");
  const trustRootPublicKeyPath = path.join(directory, "trust-root-public.pem"); await writeFile(trustRootPublicKeyPath, trustRootPublicKey.export({ type: "spki", format: "pem" }));
  const trustPayload = { schemaVersion: 1, bundleId: "fixture-production-roots", product: "Example", environment: "fixture", issuedAt, expiresAt, roles: { "assessment-gate": [trustEntry(gatePublicKey)], "product-builder": [trustEntry(builderPublic)], "protection-policy": [trustEntry(policyPublic)], "time-authority": [trustEntry(timeAuthorityPublicKey)] } };
  const trustBundlePath = path.join(directory, "trust-bundle.signed.json"); const trustBundleBytes = Buffer.from(JSON.stringify(createTrustBundleEnvelope(trustPayload, trustRootPrivateKey))); await writeFile(trustBundlePath, trustBundleBytes);
  const assessmentCore = { schemaVersion: 8, deliveryGraph: { sha256: "c".repeat(64), surfaces: [] }, status: "PASS", artifactSha256, assessmentSha256: "a".repeat(64), evidenceRootSha256: "b".repeat(64), clock: { source: "signed-live", observedAt: new Date().toISOString() }, trustBundle: { bundleId: trustPayload.bundleId, environment: trustPayload.environment, rootKeyId: keyId(trustRootPublicKey), sha256: sha(trustBundleBytes) }, protectionPolicy: { policyId: "fixture", product: "Example", keyId: keyId(policyPublic), sha256: sha(policyBytes), exposurePolicySha256: "e".repeat(64) } };
  const assessmentCoreBytes = Buffer.from(JSON.stringify(assessmentCore)); await writeFile(assessment, JSON.stringify({ ...assessmentCore, gateAttestation: { format: "rea-hardening-assessment-gate/v1", keyId: keyId(gatePublicKey), signature: sign(null, Buffer.concat([Buffer.from("rea-hardening-assessment-gate/v1\0"), assessmentCoreBytes]), gatePrivateKey).toString("base64") } }));

  git(directory, ["init"]); git(directory, ["config", "user.email", "test@example.invalid"]); git(directory, ["config", "user.name", "Test"]); git(directory, ["add", "."]); git(directory, ["commit", "-m", "fixture"]);
  const timeRoot = `${directory}-time`; await mkdir(timeRoot); const timeLedger = path.join(timeRoot, "ledger"); await mkdir(timeLedger);
  const timeAuthorityClient = await createLiveTimeAuthorityClient(timeRoot, timeAuthorityPrivateKey);
  return { directory, productRoot, buildDefinition, virtualized, buildAttestation, builderPublicPath, protectionPolicy, policyPublicPath, artifactReport, assessment, gatePublic, exposure, virtualization, transform, trustBundlePath, trustRootPublicKeyPath, timeAuthorityPrivateKey, timeAuthorityClient, timeRoot, timeLedger, trustEnvironment: trustPayload.environment };
}

function invoke(value, output) {
  return spawnSync(process.execPath, [creator, "--root", value.directory, "--product-root", value.productRoot, "--build-definition", value.buildDefinition, "--virtualization-input", value.virtualized, "--build-attestation", value.buildAttestation, "--protection-policy", value.protectionPolicy, "--artifact-report", value.artifactReport, "--assessment-result", value.assessment, "--exposure-report", value.exposure, "--virtualization-report", value.virtualization, "--transform-report", value.transform, "--trust-bundle", value.trustBundlePath, "--trust-root-public-key", value.trustRootPublicKeyPath, "--time-authority-client", value.timeAuthorityClient, "--time-ledger", value.timeLedger, "--out", output], { encoding: "utf8" });
}

test("creates provenance binding a clean product source, toolchain, protector, and release evidence", async () => {
  const value = await fixture(); const output = path.join(value.directory, "..", `${path.basename(value.directory)}-provenance.json`); const result = invoke(value, output); assert.equal(result.status, 0, result.stderr);
  const provenance = JSON.parse(await readFile(output, "utf8")); assert.equal(provenance.source.dirty, false); assert.equal(provenance.productSource.dirty, false); assert.equal(provenance.toolchain.protectorVersion, "9.9.9"); assert.match(provenance.toolchain.protectorInventorySha256, /^[a-f0-9]{64}$/); assert.match(provenance.toolchain.dependencies.closureSha256, /^[a-f0-9]{64}$/); assert.equal(provenance.release.artifactSha256, "a".repeat(64));
});

test("rejects a dirty release source tree by default", async () => {
  const value = await fixture(); await writeFile(path.join(value.directory, "scripts", "fixture.txt"), "modified"); const result = invoke(value, path.join(value.directory, "provenance.json")); assert.equal(result.status, 1); assert.match(result.stderr, /clean tree/);
});

test("rejects a clean commit whose transform receipt skips virtualization", async () => {
  const value = await fixture(); const report = JSON.parse(await readFile(value.transform, "utf8")); report.upstream.virtualization.sha256 = "0".repeat(64); await writeFile(value.transform, JSON.stringify(report)); git(value.directory, ["add", "."]); git(value.directory, ["commit", "-m", "tampered stage receipt"]);
  const result = invoke(value, path.join(value.directory, "..", `${path.basename(value.directory)}-bad-provenance.json`)); assert.equal(result.status, 1); assert.match(result.stderr, /not bound to virtualization/);
});

test("rejects a handwritten PASS without the trusted assessment-gate signature", async () => {
  const value = await fixture(); await writeFile(value.assessment, JSON.stringify({ schemaVersion: 4, status: "PASS", artifactSha256: "a".repeat(64) })); git(value.directory, ["add", "."]); git(value.directory, ["commit", "-m", "forged assessment result"]);
  const result = invoke(value, path.join(value.directory, "..", `${path.basename(value.directory)}-forged-provenance.json`)); assert.equal(result.status, 1); assert.match(result.stderr, /lacks a gate attestation/);
});
