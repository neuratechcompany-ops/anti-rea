import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createTrustBundleEnvelope } from "../scripts/trust-bundle.mjs";
import { createTimeAttestationEnvelope } from "../scripts/time-attestation.mjs";
import { inspectDependencyClosure } from "../scripts/dependency-closure.mjs";
import { createLiveTimeAuthorityClient } from "./helpers/live-time-authority.mjs";

const root = path.resolve(import.meta.dirname, "..");
const manifestTool = path.join(root, "scripts", "release-manifest.mjs");
const attestationTool = path.join(root, "scripts", "release-attestation.mjs");
const tripwireTool = path.join(root, "scripts", "llm-tripwire.mjs");
function sha(value) { return createHash("sha256").update(value).digest("hex"); }
const keyId = (key) => sha((key.type === "public" ? key : createPublicKey(key)).export({ type: "spki", format: "der" }));
const trustEntry = (key) => { const publicKey = key.type === "public" ? key : createPublicKey(key); const der = publicKey.export({ type: "spki", format: "der" }); return { keyId: sha(der), publicKeySpkiBase64: der.toString("base64") }; };
const deliverySurfaces = [
  { id: "release-primary", kind: "release", audience: "customer", disposition: "present", rationale: "release" }, { id: "update-stable", kind: "update", audience: "customer", disposition: "present", rationale: "updates" },
  { id: "crash-none", kind: "crash", audience: "none", disposition: "not-applicable", rationale: "fixture has no crash upload" }, { id: "support-none", kind: "support", audience: "none", disposition: "not-applicable", rationale: "fixture has no support export" }, { id: "symbols-none", kind: "symbols", audience: "none", disposition: "not-applicable", rationale: "fixture has no symbols" },
];
function signedEnvelope(format, payload, privateKey) {
  const bytes = Buffer.from(JSON.stringify(payload));
  return { format, keyId: keyId(privateKey), payload: bytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${format}\0`), bytes]), privateKey).toString("base64") };
}

async function fixture(policyProduct = "Example", serverExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(), clockSource = "signed-live") {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-attestation-"));
  const protectorRoot = path.join(directory, "protector"); const protectorPackage = path.join(protectorRoot, "node_modules", "fixture-dependency"); await mkdir(protectorPackage, { recursive: true });
  await writeFile(path.join(protectorRoot, "package.json"), JSON.stringify({ name: "fixture-protector", version: "1.0.0", dependencies: { "fixture-dependency": "1.0.0" } }));
  await writeFile(path.join(protectorRoot, "package-lock.json"), JSON.stringify({ name: "fixture-protector", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "fixture-protector", version: "1.0.0" }, "node_modules/fixture-dependency": { version: "1.0.0", integrity: "sha512-fixture" } } }));
  await writeFile(path.join(protectorPackage, "package.json"), JSON.stringify({ name: "fixture-dependency", version: "1.0.0" })); await writeFile(path.join(protectorPackage, "index.js"), "export const fixture = true;\n");
  const artifact = path.join(directory, "artifact"); await mkdir(artifact);
  const artifactBytes = Buffer.from("release");
  await writeFile(path.join(artifact, "app.bin"), artifactBytes);
  const tripwireRoot = path.join(artifact, "META-INF", "anti-rea"); const tripwireManifest = path.join(directory, "tripwire-manifest.json");
  const tripwireResult = spawnSync(process.execPath, [tripwireTool, "create", "--out-dir", tripwireRoot, "--manifest", tripwireManifest, "--product", "Example", "--release", "1.2.3", "--count", "5"], { encoding: "utf8" }); assert.equal(tripwireResult.status, 0, tripwireResult.stderr);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, "private.pem"); const publicPath = path.join(directory, "public.pem");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }));
  await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }));
  const { privateKey: manifestPrivateKey, publicKey: manifestPublicKey } = generateKeyPairSync("ed25519");
  const manifestPrivatePath = path.join(directory, "manifest-private.pem");
  await writeFile(manifestPrivatePath, manifestPrivateKey.export({ type: "pkcs8", format: "pem" }));
  const manifest = path.join(directory, "release.manifest.json");
  const manifestResult = spawnSync(process.execPath, [manifestTool, "create", "--root", artifact, "--private-key", manifestPrivatePath, "--product", "Example", "--release", "1.2.3", "--out", manifest], { encoding: "utf8" });
  assert.equal(manifestResult.status, 0, manifestResult.stderr);
  const manifestEnvelope = JSON.parse(await readFile(manifest, "utf8")); const manifestPayload = JSON.parse(Buffer.from(manifestEnvelope.payload, "base64").toString("utf8"));
  const artifactSha256 = sha(Buffer.from(manifestPayload.files.map((file) => `${file.path}\0${file.bytes}\0${file.sha256}`).join("\n")));
  const artifactReport = path.join(directory, "artifact-report.json");
  const assessment = path.join(directory, "assessment-result.json");
  const exposure = path.join(directory, "exposure-report.json");
  const virtualized = path.join(directory, "virtualized.js");
  const virtualization = path.join(directory, "virtualization.json");
  const transform = path.join(directory, "transform.json");
  await writeFile(virtualized, "virtualized");
  const virtualizationInputSha256 = sha(Buffer.from("virtualized"));
  const canaries = ["c".repeat(64)];
  await writeFile(virtualization, JSON.stringify({ schemaVersion: 1, transformer: { name: "anti-rea-selective-vm", version: "1.2.0" }, key: { mode: "external", provider: "function-v1", encryption: "chacha20-poly1305" }, input: { path: virtualized, sha256: virtualizationInputSha256 }, output: { path: virtualized, sha256: virtualizationInputSha256 }, functions: [{ id: "f".repeat(64), name: "fixture" }], canaries: { sha256: canaries } }));
  const virtualizationBytes = await import("node:fs/promises").then((fs) => fs.readFile(virtualization));
  await writeFile(transform, JSON.stringify({ schemaVersion: 1, transformer: { name: "javascript-obfuscator", version: "5.9.0" }, profile: { id: "javascript-vm-balanced", sha256: "0".repeat(64) }, upstream: { virtualization: { sha256: sha(virtualizationBytes), canarySha256: canaries } }, input: { sha256: sha(Buffer.from("virtualized")) }, output: { path: path.join(artifact, "app.bin"), sha256: sha(artifactBytes) } }));
  await writeFile(artifactReport, JSON.stringify({ schemaVersion: 1, status: "passed", artifactSha256, artifact }));
  const { privateKey: builderPrivate, publicKey: builderPublic } = generateKeyPairSync("ed25519");
  const builderPublicPath = path.join(directory, "builder-public.pem"); await writeFile(builderPublicPath, builderPublic.export({ type: "spki", format: "pem" }));
  const repositoryUri = "https://example.invalid/product.git"; const commit = "1".repeat(40); const tree = "2".repeat(40); const buildDefinitionSha256 = "3".repeat(64); const builderEnvironmentSha256 = "4".repeat(64);
  const issuedAt = new Date().toISOString(); const evidenceExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const buildPayload = { schemaVersion: 1, product: "Example", repositoryUri, commit, tree, buildDefinitionPath: "build.mjs", buildDefinitionSha256, virtualizationInputSha256, builderId: "fixture-builder", builderEnvironmentSha256, runId: "fixture-build", issuedAt, expiresAt: evidenceExpiresAt };
  const buildAttestation = path.join(directory, "product-build.json"); const buildBytes = Buffer.from(JSON.stringify(signedEnvelope("rea-hardening-product-build-attestation/v1", buildPayload, builderPrivate))); await writeFile(buildAttestation, buildBytes);
  const { privateKey: policyPrivate, publicKey: policyPublic } = generateKeyPairSync("ed25519");
  const policyPublicPath = path.join(directory, "policy-public.pem"); await writeFile(policyPublicPath, policyPublic.export({ type: "spki", format: "pem" }));
  const regressionTests = ["functional", "performance", "platform-security"].map((kind) => ({ kind, suiteId: `${kind}-suite`, suiteSha256: "5".repeat(64), runnerId: "fixture-runner", runnerExecutableSha256: "6".repeat(64), environmentSha256: "7".repeat(64) }));
  const dependencyClosure = await inspectDependencyClosure(protectorRoot); const protectorDependencies = { packageLockSha256: dependencyClosure.packageLockSha256, closureSha256: dependencyClosure.closureSha256 };
  const protectionTransform = { surface: "javascript", backend: "selective-vm+javascript-obfuscator", virtualizerName: "anti-rea-selective-vm", virtualizerVersion: "1.2.0", keyMode: "external", encryption: "chacha20-poly1305", transformerName: "javascript-obfuscator", transformerVersion: "5.9.0", profileId: "javascript-vm-balanced", profileSha256: "0".repeat(64), claimTier: "T1" };
  const policyPayload = { schemaVersion: 6, deliverySurfaces, policyId: "fixture", product: policyProduct, exposurePolicySha256: "e".repeat(64), productSource: { repositoryUri, commit, tree, buildDefinitionSha256, builderId: "fixture-builder", builderKeyId: keyId(builderPublic), builderEnvironmentSha256 }, protectorDependencies, protectionTransform, serverAuthorization: { environment: "production-like", channel: "stable", action: "license.activate", deploymentSha256: "d".repeat(64), configSha256: "e".repeat(64), transcriptSchemaSha256: "f".repeat(64) }, evidenceWorkerKeyIds: ["8".repeat(64)], analyzers: [{ family: "static-a", executableSha256: "9".repeat(64), adapterSha256: "a".repeat(64) }, { family: "static-b", executableSha256: "b".repeat(64), adapterSha256: "c".repeat(64) }], regressionTests, comparisons: [{ id: "FIXTURE-1", tier: "T1", targetMax: 1, minimumImprovement: 1, factIds: ["FACT-1"], requiredAnalyzerFamilies: ["static-a", "static-b"], requiredProbes: ["anti-rea-vm-runtime-hook"] }], issuedAt, expiresAt: evidenceExpiresAt };
  const protectionPolicy = path.join(directory, "protection-policy.json"); const policyBytes = Buffer.from(JSON.stringify(signedEnvelope("rea-hardening-protection-policy/v6", policyPayload, policyPrivate))); await writeFile(protectionPolicy, policyBytes);
  const { privateKey: gatePrivateKey, publicKey: gatePublicKey } = generateKeyPairSync("ed25519");
  const gatePublic = path.join(directory, "gate-public.pem");
  await writeFile(gatePublic, gatePublicKey.export({ type: "spki", format: "pem" }));
  const { publicKey: serverAuthorizationPublicKey } = generateKeyPairSync("ed25519");
  const { privateKey: timeAuthorityPrivateKey, publicKey: timeAuthorityPublicKey } = generateKeyPairSync("ed25519");
  const { privateKey: trustRootPrivateKey, publicKey: trustRootPublicKey } = generateKeyPairSync("ed25519");
  const trustRootPublicKeyPath = path.join(directory, "trust-root-public.pem");
  await writeFile(trustRootPublicKeyPath, trustRootPublicKey.export({ type: "spki", format: "pem" }));
  const trustPayload = {
    schemaVersion: 1, bundleId: "fixture-production-roots", product: "Example", environment: "production-like", issuedAt, expiresAt: evidenceExpiresAt,
    roles: {
      "assessment-gate": [trustEntry(gatePublicKey)],
      "product-builder": [trustEntry(builderPublic)],
      "protection-policy": [trustEntry(policyPublic)],
      "release-attestation": [trustEntry(publicKey)],
      "release-manifest": [trustEntry(manifestPublicKey)],
      "server-authorization": [trustEntry(serverAuthorizationPublicKey)],
      "time-authority": [trustEntry(timeAuthorityPublicKey)],
    },
  };
  const trustBundlePath = path.join(directory, "trust-bundle.signed.json");
  const trustBundleEnvelope = createTrustBundleEnvelope(trustPayload, trustRootPrivateKey);
  const trustBundleBytes = Buffer.from(JSON.stringify(trustBundleEnvelope));
  await writeFile(trustBundlePath, trustBundleBytes);
  const assessmentCore = {
    schemaVersion: 8, deliveryGraph: { sha256: "c".repeat(64), surfaces: [] }, status: "PASS", artifactSha256,
    assessmentSha256: "a".repeat(64), evidenceRootSha256: "b".repeat(64),
    clock: { source: clockSource, observedAt: new Date().toISOString() },
    trustBundle: { bundleId: trustPayload.bundleId, environment: trustPayload.environment, rootKeyId: keyId(trustRootPublicKey), sha256: sha(trustBundleBytes) },
    protectionPolicy: { policyId: "fixture", product: policyProduct, keyId: keyId(policyPublic), sha256: sha(policyBytes), exposurePolicySha256: "e".repeat(64) },
    serverAuthorization: { keyId: keyId(serverAuthorizationPublicKey), product: policyProduct, ...policyPayload.serverAuthorization, transcriptSha256: "1".repeat(64), challengeId: "2".repeat(64), challengeSha256: "3".repeat(64), issuedAt: new Date(Date.now() - 60 * 1000).toISOString(), expiresAt: serverExpiresAt },
  };
  const assessmentCoreBytes = Buffer.from(JSON.stringify(assessmentCore));
  const gateKeyId = sha(gatePublicKey.export({ type: "spki", format: "der" }));
  await writeFile(assessment, JSON.stringify({ ...assessmentCore, gateAttestation: { format: "rea-hardening-assessment-gate/v1", keyId: gateKeyId, signature: sign(null, Buffer.concat([Buffer.from("rea-hardening-assessment-gate/v1\0"), assessmentCoreBytes]), gatePrivateKey).toString("base64") } }));
  await writeFile(exposure, JSON.stringify({ schemaVersion: 1, status: "PASS", artifactVerification: { artifactSha256 } }));
  const artifactReportBytes = await readFile(artifactReport); const assessmentBytes = await readFile(assessment); const exposureBytes = await readFile(exposure); const transformBytes = await readFile(transform);
  const provenance = path.join(directory, "provenance.json");
  await writeFile(provenance, JSON.stringify({
    schemaVersion: 1, format: "rea-hardening-provenance/v4", source: { root: protectorRoot, dirty: false },
    clock: { source: "signed-live", observedAt: new Date().toISOString(), keyId: "4".repeat(64), attestationSha256: "5".repeat(64), nonce: "6".repeat(64), consumptionSha256: "7".repeat(64), requestSha256: "8".repeat(64), verifierRunId: "9".repeat(64) },
    toolchain: { dependencies: dependencyClosure },
    trustBundle: assessmentCore.trustBundle,
    productSource: { dirty: false, repositoryUri, commit, tree, buildDefinition: { path: "build.mjs", sha256: buildDefinitionSha256 }, virtualizationInput: { path: virtualized, sha256: virtualizationInputSha256 }, protectionPolicy: { path: protectionPolicy, sha256: sha(policyBytes), keyId: keyId(policyPublic) }, buildAttestation: { path: buildAttestation, sha256: sha(buildBytes), keyId: keyId(builderPublic), runId: "fixture-build", environmentSha256: builderEnvironmentSha256 } },
    release: {
      artifactSha256,
      artifactReportSha256: sha(artifactReportBytes),
      assessmentResultSha256: sha(assessmentBytes),
      assessmentGateKeyId: gateKeyId,
      exposureReportSha256: sha(exposureBytes),
      virtualizationReportSha256: sha(virtualizationBytes),
      transformReportSha256: sha(transformBytes),
    },
  }));
  const timeLedger = path.join(directory, "time-ledger"); await mkdir(timeLedger); const timeAuthorityClient = await createLiveTimeAuthorityClient(directory, timeAuthorityPrivateKey);
  return { directory, artifactReport, assessment, gatePublic, exposure, virtualization, transform, provenance, protectionPolicy, policyPublicPath, buildAttestation, builderPublicPath, tripwireRoot, tripwireManifest, manifest, privatePath, publicPath, trustBundlePath, trustRootPublicKeyPath, timeAuthorityPrivateKey, timeAuthorityClient, timeLedger, trustEnvironment: trustPayload.environment, protectorPackage };
}

function timeArgs(value) {
  return ["--time-authority-client", value.timeAuthorityClient, "--time-ledger", value.timeLedger];
}

function common(value, signedTimeArgs = timeArgs(value)) {
  return [
    "--artifact-report", value.artifactReport,
    "--assessment-result", value.assessment,
    "--exposure-report", value.exposure,
    "--virtualization-report", value.virtualization,
    "--transform-report", value.transform,
    "--provenance", value.provenance,
    "--protection-policy", value.protectionPolicy,
    "--build-attestation", value.buildAttestation,
    "--tripwire-root", value.tripwireRoot,
    "--tripwire-manifest", value.tripwireManifest,
    "--release-manifest", value.manifest,
    "--trust-bundle", value.trustBundlePath,
    "--trust-root-public-key", value.trustRootPublicKeyPath,
    ...signedTimeArgs,
    "--product", "Example", "--channel", "stable", "--release", "1.2.3",
  ];
}

test("rejects a pre-issued file time proof for release signing", async () => {
  const value = await fixture(); const nonce = randomBytes(32).toString("hex"); const timeAttestation = path.join(value.directory, "preissued-time.json"); const assessmentSha256 = sha(readFileSync(value.assessment));
  writeFileSync(timeAttestation, JSON.stringify(createTimeAttestationEnvelope({ schemaVersion: 1, product: "Example", environment: value.trustEnvironment, evaluationId: `release:${assessmentSha256}`, nonce, authorityRunId: randomBytes(32).toString("hex"), observedAt: new Date().toISOString() }, value.timeAuthorityPrivateKey)));
  const fileTimeArgs = ["--time-attestation", timeAttestation, "--time-nonce", nonce, "--time-ledger", value.timeLedger]; const output = path.join(value.directory, "preissued-release.json"); const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const result = spawnSync(process.execPath, [attestationTool, "create", ...common(value, fileTimeArgs), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", output], { encoding: "utf8" });
  assert.equal(result.status, 1); assert.match(result.stderr, /requires live-challenged time/);
});

test("rejects an installed protector dependency modified after owner precommit", async () => {
  const value = await fixture(); await writeFile(path.join(value.protectorPackage, "index.js"), "export const fixture = 'tampered';\n"); const attestation = path.join(value.directory, "dependency-tamper.json"); const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const result = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(result.status, 1); assert.match(result.stderr, /dependency closure does not match/);
});

test("signs an evidence-bound channel entry and enforces minimum sequence", async () => {
  const value = await fixture();
  const attestation = path.join(value.directory, "attestation-1.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 0, created.stderr);
  const verified = spawnSync(process.execPath, [attestationTool, "verify", ...common(value), "--attestation", attestation, "--minimum-sequence", "1"], { encoding: "utf8" });
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stdout).status, "verified");
  const rollback = spawnSync(process.execPath, [attestationTool, "verify", ...common(value), "--attestation", attestation, "--minimum-sequence", "2"], { encoding: "utf8" });
  assert.equal(rollback.status, 1);
  assert.match(rollback.stderr, /rollback rejected/);
});

test("binds a newer entry to its previous signed channel head", async () => {
  const value = await fixture();
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const first = path.join(value.directory, "attestation-1.json");
  const second = path.join(value.directory, "attestation-2.json");
  assert.equal(spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", first], { encoding: "utf8" }).status, 0);
  const next = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "2", "--expires-at", expires, "--previous-attestation", first, "--out", second], { encoding: "utf8" });
  assert.equal(next.status, 0, next.stderr);
  const missingHead = spawnSync(process.execPath, [attestationTool, "verify", ...common(value), "--attestation", second, "--minimum-sequence", "2"], { encoding: "utf8" });
  assert.equal(missingHead.status, 1);
  assert.match(missingHead.stderr, /previous attestation is required/);
  const verified = spawnSync(process.execPath, [attestationTool, "verify", ...common(value), "--attestation", second, "--minimum-sequence", "2", "--previous-attestation", first], { encoding: "utf8" });
  assert.equal(verified.status, 0, verified.stderr);
});

test("rejects a release channel not precommitted by the product owner", async () => {
  const value = await fixture();
  const args = common(value); args[args.indexOf("--channel") + 1] = "beta";
  const attestation = path.join(value.directory, "wrong-channel.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...args, "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /server authorization scope does not match release product\/channel/);
});

test("rejects a non-genesis sequence without its immediate predecessor", async () => {
  const value = await fixture();
  const attestation = path.join(value.directory, "attestation-gap.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "3", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /requires the immediate previous attestation/);
});

test("rejects a release signer that is not trusted for the release-attestation role", async () => {
  const value = await fixture();
  const { privateKey } = generateKeyPairSync("ed25519");
  const outsider = path.join(value.directory, "outsider-release-private.pem");
  await writeFile(outsider, privateKey.export({ type: "pkcs8", format: "pem" }));
  const attestation = path.join(value.directory, "attestation-outsider.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", outsider, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /is not trusted for role release-attestation/);
});

test("rejects evidence modified after signing", async () => {
  const value = await fixture();
  const attestation = path.join(value.directory, "attestation.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 0, created.stderr);
  const original = JSON.parse(await import("node:fs/promises").then((fs) => fs.readFile(value.assessment, "utf8")));
  await writeFile(value.assessment, JSON.stringify({ ...original, tampered: true }));
  const verified = spawnSync(process.execPath, [attestationTool, "verify", ...common(value), "--attestation", attestation, "--minimum-sequence", "1"], { encoding: "utf8" });
  assert.equal(verified.status, 1);
  assert.match(verified.stderr, /assessment gate signature is invalid|provenance evidence hashes do not match|evidence bindings/);
});

test("rejects a stage receipt modified after signing", async () => {
  const value = await fixture();
  const attestation = path.join(value.directory, "attestation-stage.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 0, created.stderr);
  const transform = JSON.parse(await import("node:fs/promises").then((fs) => fs.readFile(value.transform, "utf8")));
  transform.input.sha256 = "0".repeat(64);
  await writeFile(value.transform, JSON.stringify(transform));
  const verified = spawnSync(process.execPath, [attestationTool, "verify", ...common(value), "--attestation", attestation, "--minimum-sequence", "1"], { encoding: "utf8" });
  assert.equal(verified.status, 1);
  assert.match(verified.stderr, /not bound to virtualization|evidence hashes/);
});

test("rejects a release manifest with a forged signature before channel signing", async () => {
  const value = await fixture();
  const envelope = JSON.parse(await import("node:fs/promises").then((fs) => fs.readFile(value.manifest, "utf8")));
  envelope.signature = `${envelope.signature.slice(0, -2)}AA`;
  await writeFile(value.manifest, JSON.stringify(envelope));
  const attestation = path.join(value.directory, "attestation-forged-manifest.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /manifest signature is invalid/);
});

test("rejects a gate signed for a different protection-policy product", async () => {
  const value = await fixture("AnotherProduct");
  const attestation = path.join(value.directory, "attestation-cross-product.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /policy product does not match/);
});

test("rejects stale server authorization at release signing time", async () => {
  const value = await fixture("Example", new Date(Date.now() - 1000).toISOString());
  const attestation = path.join(value.directory, "attestation-stale-server.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /server authorization evidence is stale/);
});

test("rejects an assessment gate produced with caller-controlled test time", async () => {
  const value = await fixture("Example", new Date(Date.now() + 60 * 60 * 1000).toISOString(), "test-override");
  const attestation = path.join(value.directory, "attestation-test-clock.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /fresh live-challenged time/);
});

test("rejects a removed or modified agent-refusal tripwire before release signing", async () => {
  const value = await fixture();
  await writeFile(path.join(value.tripwireRoot, "AUTHORIZATION_REQUIRED.md"), "removed defensive boundary\n");
  const attestation = path.join(value.directory, "attestation-tripwire-tampered.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /tripwire|digest mismatch/);
});

test("rejects a release receipt downgraded from external to embedded key mode", async () => {
  const value = await fixture();
  const receipt = JSON.parse(await readFile(value.virtualization, "utf8"));
  receipt.key = { mode: "embedded", encryption: "embedded-xorshift" };
  await writeFile(value.virtualization, JSON.stringify(receipt));
  const attestation = path.join(value.directory, "attestation-downgrade.json");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const created = spawnSync(process.execPath, [attestationTool, "create", ...common(value), "--private-key", value.privatePath, "--sequence", "1", "--expires-at", expires, "--out", attestation], { encoding: "utf8" });
  assert.equal(created.status, 1);
  assert.match(created.stderr, /key mode or encryption differs from owner policy/);
});
