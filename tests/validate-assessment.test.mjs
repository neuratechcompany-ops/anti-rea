import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createTrustBundleEnvelope } from "../scripts/trust-bundle.mjs";
import { semanticFingerprint } from "../scripts/semantic-recovery.mjs";
import { createEvidenceChallengeEnvelope } from "../scripts/evidence-challenge.mjs";
import { inspectDeliveryGraph } from "../scripts/delivery-graph.mjs";
import { analyzeCrossBuildAlignment } from "../scripts/probe-cross-build-alignment.mjs";
import { analyzeCrossBuildSemantic } from "../scripts/probe-cross-build-semantic.mjs";
import { createTimeAttestationEnvelope } from "../scripts/time-attestation.mjs";

const root = path.resolve(import.meta.dirname, "..");
const validator = path.join(root, "scripts", "validate-assessment.mjs");
const fixtureBehaviorVector = { schemaVersion: 1, cases: [{ inputSha256: "1".repeat(64), outputSha256: "2".repeat(64), status: "returned" }, { inputSha256: "3".repeat(64), outputSha256: "4".repeat(64), status: "returned" }] };
const fixtureWat = `(module (func $discount (param $total i32) (result i32) local.get $total i32.const 100 i32.gt_s (if (result i32) (then i32.const 80) (else i32.const 100))))`;
const fixtureNativeCfg = { schemaVersion: 1, architecture: "x86-64", entry: "owner-entry", blocks: [
  { id: "owner-entry", instructions: [{ mnemonic: "cmp", operandClasses: ["register", "immediate"] }, { mnemonic: "jle", operandClasses: ["relative"] }], successors: ["owner-yes", "owner-no"] },
  { id: "owner-yes", instructions: [{ mnemonic: "imul", operandClasses: ["register", "immediate"] }, { mnemonic: "ret", operandClasses: [] }], successors: [] },
  { id: "owner-no", instructions: [{ mnemonic: "mov", operandClasses: ["register", "register"] }, { mnemonic: "ret", operandClasses: [] }], successors: [] },
] };

function sha(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function treeDigest(name, bytes) { return sha(Buffer.from(`${name}\0${bytes.length}\0${sha(bytes)}`)); }
function trustEntry(publicKey) { const der = publicKey.export({ type: "spki", format: "der" }); return { keyId: sha(der), publicKeySpkiBase64: der.toString("base64") }; }

async function writeJson(file, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  await writeFile(file, bytes);
  return sha(bytes);
}

async function buildFixture({ sameExecutable = false, comparisonTier = "T2" } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-assessment-v2-"));
  const baseline = path.join(directory, "baseline");
  const artifact = path.join(directory, "artifact");
  const negativeArtifact = path.join(directory, "negative-artifact");
  await mkdir(baseline); await mkdir(artifact); await mkdir(negativeArtifact);
  const baselineBytes = Buffer.from("baseline");
  const buildVariant = (index) => Buffer.concat([[0, 1, 2, 3].map((part) => createHash("sha256").update(`fixture-build-${index}-${part}`).digest()), [Buffer.from([index])]].flat());
  const artifactBytes = buildVariant(0);
  const negativeBytes = Buffer.from("secret=contaminated");
  await writeFile(path.join(baseline, "app.js"), baselineBytes);
  await writeFile(path.join(artifact, "app.js"), artifactBytes);
  const crossBuildPaths = [path.join(artifact, "app.js")];
  for (let index = 1; index < 20; index += 1) { const variantPath = path.join(directory, `cross-build-${index}.bin`); await writeFile(variantPath, buildVariant(index)); crossBuildPaths.push(variantPath); }
  const update = path.join(directory, "update"); await mkdir(update); await writeFile(path.join(update, "manifest.json"), "{}\n");
  await writeFile(path.join(negativeArtifact, "app.js"), negativeBytes);
  const artifactSha = treeDigest("app.js", artifactBytes);
  const artifactVerification = {
    schemaVersion: 1, artifact: await realpath(artifact), status: "passed", artifactSha256: artifactSha,
    summary: { errors: 0 },
  };
  const artifactReportSha = await writeJson(path.join(directory, "artifact-verification.json"), artifactVerification);
  const deliveryDescriptor = { schemaVersion: 1, surfaces: [
    { id: "release-primary", kind: "release", audience: "customer", path: artifact },
    { id: "update-stable", kind: "update", audience: "customer", path: update },
  ] };
  const deliveryGraphSha = await writeJson(path.join(directory, "delivery-graph.json"), await inspectDeliveryGraph(deliveryDescriptor));
  const virtualizedPath = path.join(directory, "virtualized.js"); const virtualizedBytes = Buffer.from("virtualized fixture"); await writeFile(virtualizedPath, virtualizedBytes);
  const canarySha256 = sha(Buffer.from("runtime-secret")); const profileSha256 = "0".repeat(64);
  const protectedFunctionId = "f".repeat(64);
  const virtualizationReceiptValue = { schemaVersion: 1, transformer: { name: "anti-rea-selective-vm", version: "1.2.0" }, key: { mode: "external", provider: "function-v1", encryption: "chacha20-poly1305" }, input: { path: path.join(directory, "build-input.js"), sha256: "1".repeat(64) }, output: { path: virtualizedPath, sha256: sha(virtualizedBytes) }, functions: [{ id: protectedFunctionId, name: "fixture" }], canaries: { sha256: [canarySha256] } };
  const virtualizationReceiptSha = await writeJson(path.join(directory, "virtualization.json"), virtualizationReceiptValue);
  const transformReceiptValue = { schemaVersion: 1, transformer: { name: "javascript-obfuscator", version: "5.9.0" }, profile: { id: "javascript-vm-balanced", sha256: profileSha256 }, upstream: { virtualization: { sha256: virtualizationReceiptSha, canarySha256: [canarySha256] } }, input: { sha256: sha(virtualizedBytes) }, output: { path: path.join(artifact, "app.js"), sha256: sha(artifactBytes) } };
  const transformReceiptSha = await writeJson(path.join(directory, "transform.json"), transformReceiptValue);
  const negativeReport = {
    schemaVersion: 1, artifact: await realpath(negativeArtifact), status: "failed", artifactSha256: treeDigest("app.js", negativeBytes),
    summary: { errors: 1 },
  };
  const negativeReportSha = await writeJson(path.join(directory, "negative-control.json"), negativeReport);

  const nodePath = await realpath(process.execPath);
  const stringsPath = sameExecutable ? nodePath : await realpath("/usr/bin/strings");
  const semanticExtractorPath = path.join(directory, "fixture-semantic-extractor.mjs");
  await writeFile(semanticExtractorPath, `#!/bin/sh
last=$(tail -c 1 "$1" | od -An -tu1 | tr -d ' ')
count=$((5 + last))
printf '{"schemaVersion":1,"entry":"n0","nodes":['
i=0; while [ "$i" -lt "$count" ]; do if [ "$i" -gt 0 ]; then printf ','; fi; if [ "$i" -eq 0 ]; then op=input; elif [ "$i" -eq $((count - 1)) ]; then op=return; else op=arithmetic; fi; printf '{"id":"n%s","op":"%s","valueClass":"int"}' "$i" "$op"; i=$((i + 1)); done
printf '],"controlEdges":['
i=0; while [ "$i" -lt $((count - 1)) ]; do if [ "$i" -gt 0 ]; then printf ','; fi; if [ "$i" -eq $((count - 2)) ]; then kind=return; else kind=fallthrough; fi; printf '{"from":"n%s","to":"n%s","kind":"%s"}' "$i" "$((i + 1))" "$kind"; i=$((i + 1)); done
printf '],"dataEdges":['
i=0; while [ "$i" -lt $((count - 1)) ]; do if [ "$i" -gt 0 ]; then printf ','; fi; printf '{"from":"n%s","to":"n%s","input":0}' "$i" "$((i + 1))"; i=$((i + 1)); done
printf ']}'
`); await chmod(semanticExtractorPath, 0o755);
  const semanticAdapterPath = path.join(directory, "semantic-adapter.json");
  const semanticAdapterBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, id: "fixture-semantic-ir", family: "semantic-ir", type: "probe", surfaces: ["javascript"], command: semanticExtractorPath, args: ["{artifact}"], timeoutMs: 5000, maxOutputBytes: 1024 * 1024, outputFormat: "json", requireNonEmpty: true })); await writeFile(semanticAdapterPath, semanticAdapterBytes);
  const executableIdentities = {
    rea: { path: nodePath, sha256: sha(await readFile(nodePath)) },
    "binary-strings": { path: stringsPath, sha256: sha(await readFile(stringsPath)) },
    "semantic-ir": { path: semanticExtractorPath, sha256: sha(await readFile(semanticExtractorPath)) },
  };
  const adapterIdentities = {
    rea: sha(Buffer.from("adapter:rea")),
    "binary-strings": sha(Buffer.from("adapter:binary-strings")),
    "semantic-ir": sha(semanticAdapterBytes),
  };
  const { privateKey: workerPrivateKey, publicKey: workerPublicKey } = generateKeyPairSync("ed25519");
  const { privateKey: coordinatorPrivateKey, publicKey: coordinatorPublicKey } = generateKeyPairSync("ed25519");
  const workerPublicKeyPath = path.join(directory, "evidence-worker-public.pem");
  await writeFile(workerPublicKeyPath, workerPublicKey.export({ type: "spki", format: "pem" }));
  const workerKeyId = sha(workerPublicKey.export({ type: "spki", format: "der" }));
  const evaluationId = `fixture-evaluation-${path.basename(directory)}`;
  let challengePolicySha256 = null;
  async function attest(reportSha256, artifactSha256, kind, filename, options = {}) {
    assert.match(challengePolicySha256 ?? "", /^[a-f0-9]{64}$/);
    const challengeFile = `${filename}.challenge.json`; const challengeId = options.challengeId ?? sha(Buffer.from(`${filename}\0${reportSha256}`));
    const challengePayload = {
      schemaVersion: 1, challengeId, product: "fixture-product", evaluationId, policySha256: challengePolicySha256, artifactSha256, kind, workerKeyId,
      runnerId: "fixture-isolated-runner", environmentSha256: sha(Buffer.from("fixture-runner-image")), workloadIdentity: "spiffe://fixture.test/anti-rea/evidence-worker",
      issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    };
    const challengeSha256 = await writeJson(path.join(directory, challengeFile), createEvidenceChallengeEnvelope(challengePayload, coordinatorPrivateKey));
    const payload = {
      schemaVersion: 2, kind, runId: `fixture-${filename}`, issuedAt: new Date(Date.now() - 1000).toISOString(),
      expiresAt: challengePayload.expiresAt, reportSha256, artifactSha256, challengeId, challengeSha256,
      runnerId: challengePayload.runnerId, environmentSha256: challengePayload.environmentSha256, workloadIdentity: challengePayload.workloadIdentity,
    };
    const payloadBytes = Buffer.from(JSON.stringify(payload));
    const envelope = {
      format: "rea-hardening-evidence-attestation/v2", keyId: workerKeyId, payload: payloadBytes.toString("base64"),
      signature: sign(null, Buffer.concat([Buffer.from("rea-hardening-evidence-attestation/v2\0"), payloadBytes]), workerPrivateKey).toString("base64"),
    };
    return { challenge: challengeFile, challengeSha256, attestation: filename, attestationSha256: await writeJson(path.join(directory, filename), envelope) };
  }
  const declarations = [];
  for (const phase of ["before", "after"]) {
    for (const family of ["rea", "binary-strings"]) {
      const evidence = `${phase}-${family}`;
      const evidenceDirectory = path.join(directory, evidence);
      await mkdir(evidenceDirectory);
      const stdout = Buffer.from(`${phase}:${family}`);
      const stderr = Buffer.alloc(0);
      await writeFile(path.join(evidenceDirectory, "stdout.bin"), stdout);
      await writeFile(path.join(evidenceDirectory, "stderr.bin"), stderr);
      const target = family === "binary-strings"
        ? path.join(phase === "after" ? artifact : baseline, "app.js")
        : (phase === "after" ? artifact : baseline);
      const identity = family === "binary-strings"
        ? { kind: "file", sha256: sha(phase === "after" ? artifactBytes : baselineBytes) }
        : { kind: "directory", sha256: treeDigest("app.js", phase === "after" ? artifactBytes : baselineBytes) };
      const report = {
        schemaVersion: 1,
        adapter: { id: family === "rea" ? "rea-javascript" : "strings", family, sha256: adapterIdentities[family], surfaces: ["test"] },
        artifact: await realpath(target),
        artifactIdentity: identity,
        invocation: { command: executableIdentities[family].path, executable: executableIdentities[family], args: [], timeoutMs: 1000, maxOutputBytes: 1024 },
        status: "valid", reasons: [], execution: { exitCode: 0 },
        evidence: {
          stdout: { path: "stdout.bin", bytes: stdout.length, sha256: sha(stdout) },
          stderr: { path: "stderr.bin", bytes: 0, sha256: sha(stderr) },
        },
      };
      const reportSha256 = await writeJson(path.join(evidenceDirectory, "probe.json"), report);
      declarations.push({ id: `${family}-${phase}`, family, phase, evidence, reportSha256 });
    }
  }
  const regressions = {};
  const regressionTests = [];
  const environmentSha256 = sha(Buffer.from("fixture-regression-environment"));
  for (const [name, kind] of [["functional", "functional"], ["performance", "performance"], ["platformSecurity", "platform-security"]]) {
    const suiteId = `fixture-${kind}-suite`; const runnerId = "fixture-node-runner";
    const suitePath = path.join(directory, `${kind}-suite.mjs`); const resultPath = path.join(directory, `${kind}-raw.json`);
    const suiteBytes = Buffer.from(`export const kind=${JSON.stringify(kind)};\n`); const resultBytes = Buffer.from(`${JSON.stringify({ kind, passed: true })}\n`);
    await writeFile(suitePath, suiteBytes); await writeFile(resultPath, resultBytes);
    const report = {
      format: "rea-hardening-regression-report/v1", schemaVersion: 1, kind, artifactSha256: artifactSha,
      suite: { id: suiteId, path: suitePath, sha256: sha(suiteBytes) },
      runner: { id: runnerId, executablePath: nodePath, executableSha256: executableIdentities.rea.sha256, environmentSha256 },
      startedAt: new Date(Date.now() - 2000).toISOString(), completedAt: new Date(Date.now() - 1000).toISOString(), status: "passed",
      result: { path: resultPath, bytes: resultBytes.length, sha256: sha(resultBytes) },
      summary: kind === "performance" ? { metrics: [{ id: "startup-ms", unit: "ms", value: 10, maximum: 20 }] } : { total: 2, passed: 2, failed: 0, skipped: 0 },
    };
    const reportFile = `${kind}.regression.json`; const reportSha256 = await writeJson(path.join(directory, reportFile), report);
    const payload = {
      schemaVersion: 1, kind, runId: `fixture-${kind}`, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      reportSha256, artifactSha256: artifactSha, suiteId, suiteSha256: report.suite.sha256, runnerId,
      runnerExecutableSha256: executableIdentities.rea.sha256, environmentSha256,
    };
    const payloadBytes = Buffer.from(JSON.stringify(payload));
    const envelope = { format: "rea-hardening-regression-attestation/v1", keyId: workerKeyId, payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from("rea-hardening-regression-attestation/v1\0"), payloadBytes]), workerPrivateKey).toString("base64") };
    const attestation = `${kind}.regression.attestation.json`; const attestationSha256 = await writeJson(path.join(directory, attestation), envelope);
    regressions[name] = { report: reportFile, reportSha256, attestation, attestationSha256 };
    regressionTests.push({ kind, suiteId, suiteSha256: report.suite.sha256, runnerId, runnerExecutableSha256: executableIdentities.rea.sha256, environmentSha256 });
  }
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const serverAuthPublicKey = path.join(directory, "server-auth-public.pem");
  await writeFile(serverAuthPublicKey, publicKey.export({ type: "spki", format: "pem" }));
  const issuedAt = new Date(Date.now() - 1000).toISOString();
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const serverTranscriptSchema = "server-authorization-transcript-schema.json";
  const serverTranscriptSchemaBytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, requiredScenarios: ["legitimate-client", "patched-favorable-client"] }, null, 2)}\n`);
  await writeFile(path.join(directory, serverTranscriptSchema), serverTranscriptSchemaBytes);
  const serverTranscript = "server-authorization-transcript.json";
  const serverTranscriptValue = {
    schemaVersion: 1, product: "fixture-product", environment: "fixture-staging", channel: "stable", action: "license.activate",
    deploymentSha256: sha(Buffer.from("fixture-deployment")), configSha256: sha(Buffer.from("fixture-server-config")),
    scenarios: [
      { name: "legitimate-client", mutation: "none", requestSha256: "1".repeat(64), responseSha256: "2".repeat(64), clientDecision: "allowed", serverDecision: "allowed", httpStatus: 200 },
      { name: "patched-favorable-client", mutation: "forced local allow", requestSha256: "3".repeat(64), responseSha256: "4".repeat(64), clientDecision: "allowed", serverDecision: "denied", httpStatus: 403 },
    ],
  };
  const serverTranscriptSha256 = await writeJson(path.join(directory, serverTranscript), serverTranscriptValue);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const protectedCanary = "runtime-secret";
  const adversarialReport = {
    schemaVersion: 2,
    probe: "anti-rea-vm-runtime-hook",
    artifact: { path: await realpath(path.join(artifact, "app.js")), sha256: sha(artifactBytes) },
    status: "not-recovered",
    executionError: null,
    decodedPrograms: 0,
    decodedTexts: 0,
    boundaryCoverage: Object.fromEntries(["base64-decode", "buffer-to-string", "crypto-decipher", "file-read", "ipc-post-message", "json-parse", "network-fetch", "process-output", "structured-clone", "text-decoder", "webassembly-input"].map((name) => [name, { installed: true, calls: new Set(["json-parse", "text-decoder"]).has(name) ? 1 : 0, observations: 0 }])),
    coverage: { expectedFunctionIds: [protectedFunctionId], observedFunctionIds: [protectedFunctionId], complete: true },
    canaries: { supplied: 1, suppliedSha256: [sha(Buffer.from(protectedCanary))], recovered: 0, recoveredSha256: [] },
    limitations: ["fixture probe"],
  };
  const adversarialReportSha = await writeJson(path.join(directory, "adversarial-runtime.json"), adversarialReport);
  const webcrackRoot = path.join(directory, "webcrack-package"); await mkdir(webcrackRoot);
  const webcrackEntry = path.join(webcrackRoot, "index.js"); const webcrackManifest = path.join(webcrackRoot, "package.json"); const webcrackLock = path.join(directory, "pnpm-lock.yaml");
  await writeFile(webcrackEntry, "export const fixture = true;\n");
  await writeFile(webcrackManifest, JSON.stringify({ name: "webcrack", version: "2.16.0" }));
  await writeFile(webcrackLock, "lockfileVersion: fixture\n");
  const publicReport = {
    ...adversarialReport,
    schemaVersion: 1,
    probe: "anti-rea-vm-public-deobfuscator",
    boundaryCoverage: undefined,
    decodedPrograms: 1,
    recognizedEnvelopes: 1,
    tool: {
      name: "webcrack", version: "2.16.0", node: process.versions.node,
      executable: executableIdentities.rea,
      package: {
        root: webcrackRoot,
        entry: { path: webcrackEntry, sha256: sha(await readFile(webcrackEntry)) },
        manifest: { path: webcrackManifest, sha256: sha(await readFile(webcrackManifest)) },
        lockfile: { path: webcrackLock, sha256: sha(await readFile(webcrackLock)) },
      },
      deobfuscatedSha256: sha(Buffer.from("deobfuscated fixture")),
    },
  };
  const publicReportSha = await writeJson(path.join(directory, "adversarial-public.json"), publicReport);
  const holdoutReferencePath = path.join(directory, "holdout-reference.mjs"); const holdoutCandidatePath = path.join(directory, "holdout-candidate.mjs");
  await writeFile(holdoutReferencePath, "export const reference=true;\n"); await writeFile(holdoutCandidatePath, "export const candidate=true;\n");
  const nonEquivalentBehavior = structuredClone(fixtureBehaviorVector); nonEquivalentBehavior.cases[0].outputSha256 = "5".repeat(64);
  const behaviorReport = {
    schemaVersion: 1, probe: "anti-rea-behavior-holdout", artifact: { path: await realpath(path.join(artifact, "app.js")), sha256: sha(artifactBytes) },
    runtime: executableIdentities.rea,
    reference: { path: holdoutReferencePath, sha256: sha(await readFile(holdoutReferencePath)), behavior: fixtureBehaviorVector },
    candidate: { path: holdoutCandidatePath, sha256: sha(await readFile(holdoutCandidatePath)), behavior: nonEquivalentBehavior },
    corpus: { sha256: "6".repeat(64), cases: 2, inputSha256: ["1".repeat(64), "3".repeat(64)] },
    coverage: { expectedCases: 2, referenceCases: 2, candidateCases: 2, complete: true }, status: "not-recovered", executionError: null,
    limitations: ["fixture holdout probe"],
  };
  const behaviorReportSha = await writeJson(path.join(directory, "adversarial-behavior.json"), behaviorReport);
  const exposurePolicy = {
    schemaVersion: 2,
    facts: [{
      id: "ALG-01", description: "owned client cost-only rule", classification: "COST_ONLY", impact: "none",
      tiers: ["T0", "T1", "T2"], authoritativeLocation: "client", clientImplementation: true,
      serverAuthoritative: false, canaries: [protectedCanary],
      recoverySignals: [
        { id: "decision-endpoint", kind: "endpoint", normalizedSha256: semanticFingerprint("endpoint", "https://api.example.test/v1/decision?a=1&b=2") },
        { id: "discount-structure", kind: "js-structure", normalizedSha256: semanticFingerprint("js-structure", "function discount(total, vip) { if (vip && total > 100) return total * 0.8; return total; }") },
        { id: "discount-holdout", kind: "behavior-vector", normalizedSha256: semanticFingerprint("behavior-vector", fixtureBehaviorVector) },
        { id: "discount-wasm", kind: "wasm-structure", normalizedSha256: semanticFingerprint("wasm-structure", fixtureWat) },
        { id: "discount-native", kind: "native-cfg", normalizedSha256: semanticFingerprint("native-cfg", fixtureNativeCfg) },
      ],
    }],
  };
  const exposurePolicyPath = path.join(directory, "exposure-policy.json");
  const exposurePolicySha = await writeJson(exposurePolicyPath, exposurePolicy);
  const { privateKey: policyPrivateKey, publicKey: policyPublicKey } = generateKeyPairSync("ed25519");
  const { privateKey: variantBuilderPrivateKey, publicKey: variantBuilderPublicKey } = generateKeyPairSync("ed25519");
  const policyPublicKeyPath = path.join(directory, "protection-policy-public.pem");
  await writeFile(policyPublicKeyPath, policyPublicKey.export({ type: "spki", format: "pem" }));
  const policyPayload = {
    schemaVersion: 6, policyId: "fixture-policy-1", product: "fixture-product",
    issuedAt, expiresAt, exposurePolicySha256: exposurePolicySha,
    productSource: { repositoryUri: "https://example.invalid/fixture-product.git", commit: "b".repeat(40), tree: "c".repeat(40), buildDefinitionSha256: "d".repeat(64), builderId: "fixture-builder", builderKeyId: sha(variantBuilderPublicKey.export({ type: "spki", format: "der" })), builderEnvironmentSha256: "f".repeat(64) },
    protectorDependencies: { packageLockSha256: "a".repeat(64), closureSha256: "b".repeat(64) },
    protectionTransform: { surface: "javascript", backend: "selective-vm+javascript-obfuscator", virtualizerName: "anti-rea-selective-vm", virtualizerVersion: "1.2.0", keyMode: "external", encryption: "chacha20-poly1305", transformerName: "javascript-obfuscator", transformerVersion: "5.9.0", profileId: "javascript-vm-balanced", profileSha256, claimTier: comparisonTier },
    serverAuthorization: { environment: "fixture-staging", channel: "stable", action: "license.activate", deploymentSha256: serverTranscriptValue.deploymentSha256, configSha256: serverTranscriptValue.configSha256, transcriptSchemaSha256: sha(serverTranscriptSchemaBytes) },
    deliverySurfaces: [
      { id: "release-primary", kind: "release", audience: "customer", disposition: "present", rationale: "verified release" },
      { id: "update-stable", kind: "update", audience: "customer", disposition: "present", rationale: "stable updater payload" },
      { id: "crash-none", kind: "crash", audience: "none", disposition: "not-applicable", rationale: "fixture has no crash upload" },
      { id: "support-none", kind: "support", audience: "none", disposition: "not-applicable", rationale: "fixture has no support export" },
      { id: "symbols-none", kind: "symbols", audience: "none", disposition: "not-applicable", rationale: "fixture has no symbol server" },
    ],
    evidenceWorkerKeyIds: [workerKeyId],
    regressionTests,
    analyzers: [
      { family: "rea", adapterSha256: adapterIdentities.rea, executableSha256: executableIdentities.rea.sha256 },
      { family: "binary-strings", adapterSha256: adapterIdentities["binary-strings"], executableSha256: executableIdentities["binary-strings"].sha256 },
      { family: "semantic-ir", adapterSha256: adapterIdentities["semantic-ir"], executableSha256: executableIdentities["semantic-ir"].sha256 },
    ],
    comparisons: [{
      id: "L-01", factIds: ["ALG-01"], tier: comparisonTier, targetMax: 1, minimumImprovement: 1,
      requiredAnalyzerFamilies: ["rea", "binary-strings"],
      requiredProbes: ["anti-rea-behavior-holdout", "anti-rea-cross-build-alignment", "anti-rea-cross-build-semantic", "anti-rea-vm-public-deobfuscator", "anti-rea-vm-runtime-hook"],
    }],
  };
  const policyPayloadBytes = Buffer.from(JSON.stringify(policyPayload));
  const policyPublicDer = policyPublicKey.export({ type: "spki", format: "der" });
  const policyEnvelope = {
    format: "rea-hardening-protection-policy/v6", keyId: sha(policyPublicDer), payload: policyPayloadBytes.toString("base64"),
    signature: sign(null, Buffer.concat([Buffer.from("rea-hardening-protection-policy/v6\0"), policyPayloadBytes]), policyPrivateKey).toString("base64"),
  };
  const protectionPolicySha = await writeJson(path.join(directory, "protection-policy.signed.json"), policyEnvelope);
  challengePolicySha256 = protectionPolicySha;
  let crossBuildGeneration = 0;
  async function writeCrossBuildReport() {
    crossBuildGeneration += 1; const inputs = [];
    for (const [index, variantPath] of crossBuildPaths.entries()) {
      const attestationPath = path.join(directory, `cross-build-${index}.builder-attestation.json`); const payload = {
        schemaVersion: 1, product: policyPayload.product, policySha256: protectionPolicySha, repositoryUri: policyPayload.productSource.repositoryUri,
        commit: policyPayload.productSource.commit, tree: policyPayload.productSource.tree, buildDefinitionSha256: policyPayload.productSource.buildDefinitionSha256,
        builderId: policyPayload.productSource.builderId, builderEnvironmentSha256: policyPayload.productSource.builderEnvironmentSha256,
        runId: `cross-build-${crossBuildGeneration}-${index}`, variantOrdinal: index, diversitySeedCommitment: sha(Buffer.from(`seed-${crossBuildGeneration}-${index}`)),
        regionSha256: sha(await readFile(variantPath)), issuedAt, expiresAt,
      };
      const payloadBytes = Buffer.from(JSON.stringify(payload)); const envelope = { format: "rea-hardening-cross-build-variant/v1", keyId: policyPayload.productSource.builderKeyId, payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from("rea-hardening-cross-build-variant/v1\0"), payloadBytes]), variantBuilderPrivateKey).toString("base64") };
      await writeJson(attestationPath, envelope); inputs.push({ path: variantPath, attestation: attestationPath });
    }
    const report = await analyzeCrossBuildAlignment(path.join(artifact, "app.js"), inputs); const reportSha = await writeJson(path.join(directory, "adversarial-cross-build.json"), report); return { report, reportSha, inputs };
  }
  const initialCrossBuild = await writeCrossBuildReport(); const crossBuildReportSha = initialCrossBuild.reportSha;
  const semanticCrossBuildReport = await analyzeCrossBuildSemantic(path.join(artifact, "app.js"), initialCrossBuild.inputs, semanticAdapterPath); const semanticCrossBuildReportSha = await writeJson(path.join(directory, "adversarial-cross-build-semantic.json"), semanticCrossBuildReport);
  const serverChallengeFile = "server-authorization.challenge.json";
  const serverChallengePayload = { schemaVersion: 1, challengeId: sha(Buffer.from(`${evaluationId}\0server-authorization`)), product: "fixture-product", evaluationId, policySha256: protectionPolicySha, artifactSha256: artifactSha, kind: "server-authorization", workerKeyId: sha(publicDer), runnerId: "fixture-server-auth-runner", environmentSha256: policyPayload.serverAuthorization.deploymentSha256, workloadIdentity: "spiffe://fixture.test/anti-rea/server-authorization", issuedAt, expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString() };
  const serverChallengeSha256 = await writeJson(path.join(directory, serverChallengeFile), createEvidenceChallengeEnvelope(serverChallengePayload, coordinatorPrivateKey));
  const serverPayload = { schemaVersion: 2, product: "fixture-product", artifactSha256: artifactSha, ...policyPayload.serverAuthorization, transcriptSha256: serverTranscriptSha256, challengeId: serverChallengePayload.challengeId, challengeSha256: serverChallengeSha256, issuedAt, expiresAt };
  const serverPayloadBytes = Buffer.from(JSON.stringify(serverPayload));
  const serverEnvelope = { format: "rea-hardening-server-authorization/v2", keyId: sha(publicDer), payload: serverPayloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from("rea-hardening-server-authorization/v2\0"), serverPayloadBytes]), privateKey).toString("base64") };
  const serverEvidence = "server-authorization.json";
  const serverEvidenceSha = await writeJson(path.join(directory, serverEvidence), serverEnvelope);
  regressions.serverAuthorization = { status: "passed", evidence: serverEvidence, sha256: serverEvidenceSha, transcript: serverTranscript, transcriptSha256: serverTranscriptSha256, transcriptSchema: serverTranscriptSchema, transcriptSchemaSha256: sha(serverTranscriptSchemaBytes), challenge: serverChallengeFile, challengeSha256: serverChallengeSha256 };
  for (const declaration of declarations) {
    const report = JSON.parse(await readFile(path.join(directory, declaration.evidence, "probe.json"), "utf8"));
    Object.assign(declaration, await attest(declaration.reportSha256, report.artifactIdentity.sha256, "analyzer-probe", `${declaration.evidence}.attestation.json`));
  }
  const adversarialRuntimeAttestation = await attest(adversarialReportSha, sha(artifactBytes), "adversarial-probe", "adversarial-runtime.attestation.json");
  const adversarialPublicAttestation = await attest(publicReportSha, sha(artifactBytes), "adversarial-probe", "adversarial-public.attestation.json");
  const adversarialBehaviorAttestation = await attest(behaviorReportSha, sha(artifactBytes), "adversarial-probe", "adversarial-behavior.attestation.json");
  const adversarialCrossBuildAttestation = await attest(crossBuildReportSha, sha(artifactBytes), "adversarial-probe", "adversarial-cross-build.attestation.json");
  const adversarialSemanticCrossBuildAttestation = await attest(semanticCrossBuildReportSha, sha(artifactBytes), "adversarial-probe", "adversarial-cross-build-semantic.attestation.json");
  const document = {
    schemaVersion: 6,
    evaluationId,
    protectionPolicy: { path: "protection-policy.signed.json", sha256: protectionPolicySha },
    protectionReceipts: { virtualization: { path: "virtualization.json", sha256: virtualizationReceiptSha }, transform: { path: "transform.json", sha256: transformReceiptSha } },
    exposurePolicy: { path: "exposure-policy.json", sha256: exposurePolicySha },
    artifactVerification: { path: "artifact-verification.json", sha256: artifactReportSha },
    deliveryGraph: { path: "delivery-graph.json", sha256: deliveryGraphSha },
    probes: declarations,
    comparisons: [{
      id: "L-01", tier: comparisonTier, targetMax: 1,
      before: { score: 4, probeIds: ["rea-before", "binary-strings-before"] },
      after: { score: 1, probeIds: ["rea-after", "binary-strings-after"] },
    }],
    adversarialProbes: [
      { id: "A-VM-RUNTIME", tier: "T2", comparisonIds: ["L-01"], evidence: "adversarial-runtime.json", reportSha256: adversarialReportSha, ...adversarialRuntimeAttestation },
      { id: "A-PUBLIC-DEOBFUSCATOR", tier: "T1", comparisonIds: ["L-01"], evidence: "adversarial-public.json", reportSha256: publicReportSha, ...adversarialPublicAttestation },
      { id: "A-BEHAVIOR-HOLDOUT", tier: "T1", comparisonIds: ["L-01"], evidence: "adversarial-behavior.json", reportSha256: behaviorReportSha, ...adversarialBehaviorAttestation },
      { id: "A-CROSS-BUILD", tier: "T1", comparisonIds: ["L-01"], evidence: "adversarial-cross-build.json", reportSha256: crossBuildReportSha, ...adversarialCrossBuildAttestation },
      { id: "A-CROSS-BUILD-SEMANTIC", tier: "T1", comparisonIds: ["L-01"], evidence: "adversarial-cross-build-semantic.json", reportSha256: semanticCrossBuildReportSha, ...adversarialSemanticCrossBuildAttestation },
    ],
    regressions,
    negativeControl: { path: "negative-control.json", sha256: negativeReportSha },
    residualRisks: ["runtime plaintext remains observable"],
  };
  const assessment = path.join(directory, "assessment.json");
  const challengeLedger = path.join(directory, "challenge-ledger");
  await mkdir(challengeLedger);
  await writeJson(assessment, document);
  const { privateKey: trustRootPrivateKey, publicKey: trustRootPublicKey } = generateKeyPairSync("ed25519");
  const { privateKey: timeAuthorityPrivateKey, publicKey: timeAuthorityPublicKey } = generateKeyPairSync("ed25519");
  const trustRootPublicKeyPath = path.join(directory, "trust-root-public.pem");
  await writeFile(trustRootPublicKeyPath, trustRootPublicKey.export({ type: "spki", format: "pem" }));
  const trustPayload = {
    schemaVersion: 1, bundleId: "fixture-production-roots", product: "fixture-product", environment: "fixture-staging", issuedAt, expiresAt,
    roles: {
      "protection-policy": [trustEntry(policyPublicKey)],
      "evidence-worker": [trustEntry(workerPublicKey)],
      "evidence-coordinator": [trustEntry(coordinatorPublicKey)],
      "server-authorization": [trustEntry(publicKey)],
      "product-builder": [trustEntry(variantBuilderPublicKey)],
      "time-authority": [trustEntry(timeAuthorityPublicKey)],
    },
  };
  const trustBundlePath = path.join(directory, "trust-bundle.signed.json");
  await writeJson(trustBundlePath, createTrustBundleEnvelope(trustPayload, trustRootPrivateKey));
  const timeNonce = "a".repeat(64); const timeAttestationPath = path.join(directory, "time-attestation.json");
  await writeJson(timeAttestationPath, createTimeAttestationEnvelope({ schemaVersion: 1, product: trustPayload.product, environment: trustPayload.environment, evaluationId, nonce: timeNonce, authorityRunId: sha(Buffer.from(`time-${evaluationId}`)), observedAt: new Date().toISOString() }, timeAuthorityPrivateKey));
  const timeAuthorityClient = path.join(directory, "time-authority-client.mjs"); const timeModule = path.join(root, "scripts", "time-attestation.mjs"); const timePrivatePem = timeAuthorityPrivateKey.export({ type: "pkcs8", format: "pem" });
  await writeFile(timeAuthorityClient, `#!/usr/bin/env node\nimport crypto from "node:crypto";import {createTimeAttestationEnvelope} from ${JSON.stringify(timeModule)};let input="";for await(const chunk of process.stdin)input+=chunk;const request=JSON.parse(input);const envelope=createTimeAttestationEnvelope({schemaVersion:1,product:request.product,environment:request.environment,evaluationId:request.evaluationId,nonce:request.nonce,authorityRunId:crypto.randomBytes(32).toString("hex"),observedAt:new Date().toISOString()},${JSON.stringify(timePrivatePem)});process.stdout.write(JSON.stringify(envelope));\n`); await chmod(timeAuthorityClient, 0o755);
  return { directory, assessment, challengeLedger, document, adversarialReport, serverAuthPrivateKey: privateKey, serverAuthPublicKey, policyPublicKeyPath, workerPublicKeyPath, workerPrivateKey, workerKeyId, policyPayload, protectedCanary, attest, writeCrossBuildReport, semanticAdapterPath, semanticExtractorPath, crossBuildPaths, trustBundlePath, trustRootPublicKeyPath, trustRootPrivateKey, trustPayload, timeAttestationPath, timeNonce, timeAuthorityClient };
}

function run(assessment, trustBundle, trustRootPublicKey, challengeLedger = path.join(path.dirname(assessment), "challenge-ledger"), timeAttestation = path.join(path.dirname(assessment), "time-attestation.json"), timeNonce = "a".repeat(64)) {
  return spawnSync(process.execPath, [validator, assessment, "--trust-bundle", trustBundle, "--trust-root-public-key", trustRootPublicKey, "--challenge-ledger", challengeLedger, "--time-attestation", timeAttestation, "--time-nonce", timeNonce], { encoding: "utf8" });
}

test("accepts an evidence-bound two-family before/after assessment", async () => {
  const fixture = await buildFixture();
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, "PASS");
  assert.equal(report.clock.source, "signed-remote"); assert.match(report.clock.attestationSha256, /^[a-f0-9]{64}$/); assert.match(report.clock.consumptionSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(report.validProbeFamilies, ["binary-strings", "rea"]);
});

test("rejects production assessment without signed remote time", async () => {
  const fixture = await buildFixture(); const result = spawnSync(process.execPath, [validator, fixture.assessment, "--trust-bundle", fixture.trustBundlePath, "--trust-root-public-key", fixture.trustRootPublicKeyPath, "--challenge-ledger", fixture.challengeLedger], { encoding: "utf8" });
  assert.equal(result.status, 1); assert.match(result.stderr, /production assessment requires --time-authority-client/);
});

test("rejects a signed time proof under the wrong nonce", async () => {
  const fixture = await buildFixture(); const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath, fixture.challengeLedger, fixture.timeAttestationPath, "b".repeat(64));
  assert.equal(result.status, 1); assert.match(result.stderr, /time attestation nonce mismatch/);
});

test("rejects a time authority outside the offline-root trust bundle", async () => {
  const fixture = await buildFixture(); const current = JSON.parse(await readFile(fixture.timeAttestationPath, "utf8")); const payload = JSON.parse(Buffer.from(current.payload, "base64").toString("utf8")); const attacker = generateKeyPairSync("ed25519"); await writeJson(fixture.timeAttestationPath, createTimeAttestationEnvelope(payload, attacker.privateKey));
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath, fixture.challengeLedger, fixture.timeAttestationPath, fixture.timeNonce); assert.equal(result.status, 1); assert.match(result.stderr, /not trusted for role time-authority/);
});

test("rejects a delivery surface modified after its graph was recorded", async () => {
  const fixture = await buildFixture();
  const graph = JSON.parse(await readFile(path.join(fixture.directory, fixture.document.deliveryGraph.path), "utf8"));
  const update = graph.surfaces.find((item) => item.kind === "update");
  await writeFile(path.join(update.path, "late-debug.ts"), "export const secret = 1;\n");
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /changed after graph verification/);
});

test("rejects a signed delivery surface omitted from the assessment", async () => {
  const fixture = await buildFixture();
  const graphPath = path.join(fixture.directory, fixture.document.deliveryGraph.path);
  const graph = JSON.parse(await readFile(graphPath, "utf8")); graph.surfaces = graph.surfaces.filter((item) => item.kind !== "update");
  graph.descriptorSha256 = sha(Buffer.from(JSON.stringify({ schemaVersion: 1, surfaces: graph.surfaces.map(({ id, kind, audience, path: surfacePath }) => ({ id, kind, audience, path: surfacePath })) })));
  fixture.document.deliveryGraph.sha256 = await writeJson(graphPath, graph); await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /omits or adds an owner-precommitted surface/);
});

test("rejects coordinator challenge replay in a later assessment process", async () => {
  const fixture = await buildFixture();
  const first = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath, fixture.challengeLedger);
  assert.equal(first.status, 0, first.stderr);
  const second = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath, fixture.challengeLedger);
  assert.equal(second.status, 1);
  assert.match(second.stderr, /already consumed/);
});

test("rejects coordinator challenge replay across two otherwise valid probes", async () => {
  const fixture = await buildFixture();
  const first = fixture.document.probes[0]; const second = fixture.document.probes[1];
  const firstEnvelope = JSON.parse(await readFile(path.join(fixture.directory, first.challenge), "utf8"));
  const firstPayload = JSON.parse(Buffer.from(firstEnvelope.payload, "base64").toString("utf8"));
  const secondReport = JSON.parse(await readFile(path.join(fixture.directory, second.evidence, "probe.json"), "utf8"));
  Object.assign(second, await fixture.attest(second.reportSha256, secondReport.artifactIdentity.sha256, "analyzer-probe", "replayed-second.attestation.json", { challengeId: firstPayload.challengeId }));
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /reuses evidence challenge/);
});

test("rejects a coordinator challenge modified after the worker attestation", async () => {
  const fixture = await buildFixture(); const declaration = fixture.document.probes[0];
  await writeFile(path.join(fixture.directory, declaration.challenge), "{}\n");
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /challenge hash mismatch/);
});

test("rejects an embedded-key receipt under an external-key owner policy", async () => {
  const fixture = await buildFixture({ comparisonTier: "T1" });
  const receiptPath = path.join(fixture.directory, "virtualization.json");
  const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
  receipt.key = { mode: "embedded", encryption: "embedded-xorshift" };
  fixture.document.protectionReceipts.virtualization.sha256 = await writeJson(receiptPath, receipt);
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /key mode or encryption differs from owner policy/);
});

test("rejects a transform profile substituted after owner precommit", async () => {
  const fixture = await buildFixture();
  const receiptPath = path.join(fixture.directory, "transform.json");
  const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
  receipt.profile.id = "javascript-balanced";
  fixture.document.protectionReceipts.transform.sha256 = await writeJson(receiptPath, receipt);
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /profile differs from owner policy/);
});

test("rejects not-recovered evidence that omits a protected function ID", async () => {
  const fixture = await buildFixture();
  const reportPath = path.join(fixture.directory, "adversarial-public.json");
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  report.coverage.observedFunctionIds = [];
  report.coverage.complete = false;
  const reportSha256 = await writeJson(reportPath, report);
  const declaration = fixture.document.adversarialProbes.find((item) => item.id === "A-PUBLIC-DEOBFUSCATOR");
  declaration.reportSha256 = reportSha256;
  Object.assign(declaration, await fixture.attest(reportSha256, report.artifact.sha256, "adversarial-probe", "adversarial-public.attestation.json"));
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /does not cover every protected function ID/);
});

test("rejects missing or modified raw evidence", async () => {
  const fixture = await buildFixture();
  await writeFile(path.join(fixture.directory, "after-rea", "stdout.bin"), "tampered");
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /stdout evidence was modified/);
});

test("rejects analyzer aliases that resolve to one executable identity", async () => {
  const fixture = await buildFixture({ sameExecutable: true });
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /same executable identity/);
});

test("rejects the old forgeable schema and nonexistent evidence", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-assessment-forged-"));
  const assessment = path.join(directory, "assessment.json");
  await writeJson(assessment, {
    schemaVersion: 1, artifactSha256: "0".repeat(64), probes: [], comparisons: [],
    regressions: { functional: "passed", performance: "measured", platformSecurity: "passed" }, residualRisks: [],
  });
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPath = path.join(directory, "public.pem");
  await writeFile(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }));
  const result = run(assessment, publicKeyPath, publicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /fields must be exactly|schemaVersion/);
});

test("returns FAIL when a bound comparison misses its threshold", async () => {
  const fixture = await buildFixture();
  fixture.document.comparisons[0].after.score = 3;
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, "FAIL");
});

test("returns FAIL when the bound runtime attack recovers protected facts", async () => {
  const fixture = await buildFixture();
  fixture.adversarialReport.status = "recovered";
  fixture.adversarialReport.canaries.recovered = 1;
  fixture.adversarialReport.canaries.recoveredSha256 = [sha(Buffer.from("runtime-secret"))];
  const reportSha256 = await writeJson(path.join(fixture.directory, "adversarial-runtime.json"), fixture.adversarialReport);
  fixture.document.adversarialProbes[0].reportSha256 = reportSha256;
  Object.assign(fixture.document.adversarialProbes[0], await fixture.attest(reportSha256, fixture.adversarialReport.artifact.sha256, "adversarial-probe", "adversarial-runtime.attestation.json"));
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr);
  assert.match(JSON.parse(result.stdout).failures.join("\n"), /T2 adversarial attack recovered 1 canary/);
});

test("rejects a runtime report with an omitted plaintext boundary hook", async () => {
  const fixture = await buildFixture(); fixture.adversarialReport.boundaryCoverage["ipc-post-message"].installed = false;
  const reportSha256 = await writeJson(path.join(fixture.directory, "adversarial-runtime.json"), fixture.adversarialReport); const declaration = fixture.document.adversarialProbes[0]; declaration.reportSha256 = reportSha256;
  Object.assign(declaration, await fixture.attest(reportSha256, fixture.adversarialReport.artifact.sha256, "adversarial-probe", "adversarial-runtime.attestation.json")); await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath); assert.equal(result.status, 1); assert.match(result.stderr, /runtime boundary ipc-post-message is not fully installed/);
});

test("returns FAIL when the isolated holdout oracle confirms recovered behavior", async () => {
  const fixture = await buildFixture(); const reportPath = path.join(fixture.directory, "adversarial-behavior.json");
  const report = JSON.parse(await readFile(reportPath, "utf8")); report.candidate.behavior = structuredClone(report.reference.behavior); report.status = "recovered";
  const reportSha256 = await writeJson(reportPath, report); const declaration = fixture.document.adversarialProbes.find((item) => item.id === "A-BEHAVIOR-HOLDOUT");
  declaration.reportSha256 = reportSha256; Object.assign(declaration, await fixture.attest(reportSha256, report.artifact.sha256, "adversarial-probe", "adversarial-behavior.attestation.json"));
  await writeJson(fixture.assessment, fixture.document); const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr); assert.match(JSON.parse(result.stdout).failures.join("\n"), /recovered 2 holdout cases/);
});

test("returns FAIL when twenty diversified builds retain an alignable stable region", async () => {
  const fixture = await buildFixture(); const declaration = fixture.document.adversarialProbes.find((item) => item.id === "A-CROSS-BUILD"); const reportPath = path.join(fixture.directory, declaration.evidence);
  const original = JSON.parse(await readFile(reportPath, "utf8")); const artifactBytes = await readFile(original.artifact.path); const paths = original.variants.map((item) => item.path);
  for (let index = 1; index < paths.length; index += 1) {
    const suffix = Buffer.concat([createHash("sha256").update(`aligned-${index}-a`).digest(), createHash("sha256").update(`aligned-${index}-b`).digest()]);
    await writeFile(paths[index], Buffer.concat([artifactBytes.subarray(0, 64), suffix]));
  }
  const rebuilt = await fixture.writeCrossBuildReport(); const recovered = rebuilt.report; assert.equal(recovered.status, "recovered");
  declaration.reportSha256 = rebuilt.reportSha; Object.assign(declaration, await fixture.attest(declaration.reportSha256, recovered.artifact.sha256, "adversarial-probe", "adversarial-cross-build.attestation.json"));
  const semanticReport = await analyzeCrossBuildSemantic(paths[0], rebuilt.inputs, fixture.semanticAdapterPath); const semanticReportSha = await writeJson(path.join(fixture.directory, "adversarial-cross-build-semantic.json"), semanticReport); const semanticDeclaration = fixture.document.adversarialProbes.find((item) => item.id === "A-CROSS-BUILD-SEMANTIC"); semanticDeclaration.reportSha256 = semanticReportSha; Object.assign(semanticDeclaration, await fixture.attest(semanticReportSha, semanticReport.artifact.sha256, "adversarial-probe", "adversarial-cross-build-semantic.attestation.json"));
  await writeJson(fixture.assessment, fixture.document); const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr); assert.match(JSON.parse(result.stdout).failures.join("\n"), /cross-build.*recovered [1-9][0-9]* aligned windows/i);
});

test("returns FAIL when diversified bytes still lift to aligned semantic IR", async () => {
  const fixture = await buildFixture();
  for (const [index, variantPath] of fixture.crossBuildPaths.entries()) if (index > 0) await writeFile(variantPath, Buffer.concat([createHash("sha256").update(`semantic-stable-${index}-a`).digest(), createHash("sha256").update(`semantic-stable-${index}-b`).digest(), Buffer.from([0])]));
  const rebuilt = await fixture.writeCrossBuildReport(); const byteDeclaration = fixture.document.adversarialProbes.find((item) => item.id === "A-CROSS-BUILD"); byteDeclaration.reportSha256 = rebuilt.reportSha; Object.assign(byteDeclaration, await fixture.attest(rebuilt.reportSha, rebuilt.report.artifact.sha256, "adversarial-probe", "adversarial-cross-build.attestation.json"));
  const semanticReport = await analyzeCrossBuildSemantic(fixture.crossBuildPaths[0], rebuilt.inputs, fixture.semanticAdapterPath); assert.equal(semanticReport.status, "recovered"); const semanticReportSha = await writeJson(path.join(fixture.directory, "adversarial-cross-build-semantic.json"), semanticReport);
  const semanticDeclaration = fixture.document.adversarialProbes.find((item) => item.id === "A-CROSS-BUILD-SEMANTIC"); semanticDeclaration.reportSha256 = semanticReportSha; Object.assign(semanticDeclaration, await fixture.attest(semanticReportSha, semanticReport.artifact.sha256, "adversarial-probe", "adversarial-cross-build-semantic.attestation.json"));
  await writeJson(fixture.assessment, fixture.document); const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath); assert.equal(result.status, 2, result.stderr); assert.match(JSON.parse(result.stdout).failures.join("\n"), /semantic.*recovered [1-9][0-9]* aligned semantic variants/i);
});

test("rejects omission of the mandatory semantic cross-build attack", async () => {
  const fixture = await buildFixture(); fixture.document.adversarialProbes = fixture.document.adversarialProbes.filter((item) => item.id !== "A-CROSS-BUILD-SEMANTIC"); await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath); assert.equal(result.status, 1); assert.match(result.stderr, /mandatory T1 semantic cross-build attack|required adversarial probe anti-rea-cross-build-semantic/);
});

test("rejects a semantic extractor changed after its report", async () => {
  const fixture = await buildFixture(); await writeFile(fixture.semanticExtractorPath, "#!/bin/sh\nexit 0\n"); const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1); assert.match(result.stderr, /semantic tool changed after analysis/);
});

test("rejects decoy canaries even when a handwritten attack report is self-consistent", async () => {
  const fixture = await buildFixture();
  const reportPath = path.join(fixture.directory, "adversarial-runtime.json");
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  report.canaries.suppliedSha256 = [sha(Buffer.from("harmless-decoy"))];
  fixture.document.adversarialProbes[0].reportSha256 = await writeJson(reportPath, report);
  Object.assign(fixture.document.adversarialProbes[0], await fixture.attest(fixture.document.adversarialProbes[0].reportSha256, report.artifact.sha256, "adversarial-probe", "adversarial-runtime.attestation.json"));
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /supplied canaries do not match the owner-approved facts/);
});

test("derives a failing score when analyzer evidence contains an approved canary", async () => {
  const fixture = await buildFixture();
  const evidenceDirectory = path.join(fixture.directory, "after-rea");
  const stdout = Buffer.from(`recovered:${fixture.protectedCanary}`);
  await writeFile(path.join(evidenceDirectory, "stdout.bin"), stdout);
  const reportPath = path.join(evidenceDirectory, "probe.json");
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  report.evidence.stdout = { path: "stdout.bin", bytes: stdout.length, sha256: sha(stdout) };
  const declaration = fixture.document.probes.find((item) => item.id === "rea-after");
  declaration.reportSha256 = await writeJson(reportPath, report);
  Object.assign(declaration, await fixture.attest(declaration.reportSha256, report.artifactIdentity.sha256, "analyzer-probe", "after-rea.attestation.json"));
  fixture.document.comparisons[0].after.score = 0;
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr);
  assert.match(JSON.parse(result.stdout).failures.join("\n"), /evidence-derived after score 4 exceeds target 1/);
});

test("derives a failing score from normalized semantic recovery without a literal canary", async () => {
  const fixture = await buildFixture();
  const evidenceDirectory = path.join(fixture.directory, "after-rea");
  const stdout = Buffer.from('{"recoveredEndpoint":"HTTPS://API.EXAMPLE.TEST/v1/decision?b=2&a=1"}\n');
  await writeFile(path.join(evidenceDirectory, "stdout.bin"), stdout);
  const reportPath = path.join(evidenceDirectory, "probe.json");
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  report.evidence.stdout = { path: "stdout.bin", bytes: stdout.length, sha256: sha(stdout) };
  const declaration = fixture.document.probes.find((item) => item.id === "rea-after");
  declaration.reportSha256 = await writeJson(reportPath, report);
  Object.assign(declaration, await fixture.attest(declaration.reportSha256, report.artifactIdentity.sha256, "analyzer-probe", "after-rea.attestation.json"));
  fixture.document.comparisons[0].after.score = 0;
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.match(output.failures.join("\n"), /evidence-derived after score 3 exceeds target 1/);
  assert.deepEqual(output.semanticRecovery[0].afterMatches, [{ factId: "ALG-01", signalId: "decision-endpoint", kind: "endpoint", score: 3 }]);
});

test("detects recovered business logic after identifiers and constants are rewritten", async () => {
  const fixture = await buildFixture();
  const evidenceDirectory = path.join(fixture.directory, "after-rea");
  const stdout = Buffer.from("function a(x, y) { if (y && x > 999) return x * 0.1; return x; }\n");
  await writeFile(path.join(evidenceDirectory, "stdout.bin"), stdout);
  const reportPath = path.join(evidenceDirectory, "probe.json");
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  report.evidence.stdout = { path: "stdout.bin", bytes: stdout.length, sha256: sha(stdout) };
  const declaration = fixture.document.probes.find((item) => item.id === "rea-after");
  declaration.reportSha256 = await writeJson(reportPath, report);
  Object.assign(declaration, await fixture.attest(declaration.reportSha256, report.artifactIdentity.sha256, "analyzer-probe", "after-rea.attestation.json"));
  fixture.document.comparisons[0].after.score = 0;
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.match(output.failures.join("\n"), /evidence-derived after score 4 exceeds target 1/);
  assert.ok(output.semanticRecovery[0].afterMatches.some((item) => item.signalId === "discount-structure" && item.kind === "js-structure"));
});

test("detects an equivalent recovered algorithm through an owner holdout behavior vector", async () => {
  const fixture = await buildFixture();
  const evidenceDirectory = path.join(fixture.directory, "after-rea");
  const stdout = Buffer.from(`${JSON.stringify({ recoveredBehavior: { schemaVersion: 1, cases: [...fixtureBehaviorVector.cases].reverse() } })}\n`);
  await writeFile(path.join(evidenceDirectory, "stdout.bin"), stdout);
  const reportPath = path.join(evidenceDirectory, "probe.json");
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  report.evidence.stdout = { path: "stdout.bin", bytes: stdout.length, sha256: sha(stdout) };
  const declaration = fixture.document.probes.find((item) => item.id === "rea-after");
  declaration.reportSha256 = await writeJson(reportPath, report);
  Object.assign(declaration, await fixture.attest(declaration.reportSha256, report.artifactIdentity.sha256, "analyzer-probe", "after-rea.attestation.json"));
  fixture.document.comparisons[0].after.score = 0;
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.match(output.failures.join("\n"), /evidence-derived after score 4 exceeds target 1/);
  assert.ok(output.semanticRecovery[0].afterMatches.some((item) => item.signalId === "discount-holdout" && item.kind === "behavior-vector"));
});

test("detects recovered WASM logic after symbol and literal rewriting", async () => {
  const fixture = await buildFixture(); const evidenceDirectory = path.join(fixture.directory, "after-rea");
  const recovered = `(module (func $a (param $x i32) (result i32) local.get $x i32.const 999 i32.gt_s (if (result i32) (then i32.const 1) (else i32.const 2))))`;
  const stdout = Buffer.from(`${JSON.stringify({ wat: recovered })}\n`); await writeFile(path.join(evidenceDirectory, "stdout.bin"), stdout);
  const reportPath = path.join(evidenceDirectory, "probe.json"); const report = JSON.parse(await readFile(reportPath, "utf8")); report.evidence.stdout = { path: "stdout.bin", bytes: stdout.length, sha256: sha(stdout) };
  const declaration = fixture.document.probes.find((item) => item.id === "rea-after"); declaration.reportSha256 = await writeJson(reportPath, report); Object.assign(declaration, await fixture.attest(declaration.reportSha256, report.artifactIdentity.sha256, "analyzer-probe", "after-rea.attestation.json"));
  fixture.document.comparisons[0].after.score = 0; await writeJson(fixture.assessment, fixture.document); const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr); const output = JSON.parse(result.stdout); assert.ok(output.semanticRecovery[0].afterMatches.some((item) => item.signalId === "discount-wasm" && item.kind === "wasm-structure"));
});

test("detects recovered native control flow after block, address, and register rewriting", async () => {
  const fixture = await buildFixture(); const evidenceDirectory = path.join(fixture.directory, "after-rea");
  const recovered = { schemaVersion: 1, architecture: "X86-64", entry: "entry", blocks: [
    { id: "fallback", instructions: [{ mnemonic: "mov", operandClasses: ["register", "register"] }, { mnemonic: "ret", operandClasses: [] }], successors: [] },
    { id: "entry", instructions: [{ mnemonic: "cmp", operandClasses: ["register", "immediate"] }, { mnemonic: "jle", operandClasses: ["relative"] }], successors: ["discount", "fallback"] },
    { id: "discount", instructions: [{ mnemonic: "imul", operandClasses: ["register", "immediate"] }, { mnemonic: "ret", operandClasses: [] }], successors: [] },
  ] };
  const stdout = Buffer.from(`${JSON.stringify({ cfg: recovered })}\n`); await writeFile(path.join(evidenceDirectory, "stdout.bin"), stdout);
  const reportPath = path.join(evidenceDirectory, "probe.json"); const report = JSON.parse(await readFile(reportPath, "utf8")); report.evidence.stdout = { path: "stdout.bin", bytes: stdout.length, sha256: sha(stdout) };
  const declaration = fixture.document.probes.find((item) => item.id === "rea-after"); declaration.reportSha256 = await writeJson(reportPath, report); Object.assign(declaration, await fixture.attest(declaration.reportSha256, report.artifactIdentity.sha256, "analyzer-probe", "after-rea.attestation.json"));
  fixture.document.comparisons[0].after.score = 0; await writeJson(fixture.assessment, fixture.document); const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 2, result.stderr); const output = JSON.parse(result.stdout); assert.ok(output.semanticRecovery[0].afterMatches.some((item) => item.signalId === "discount-native" && item.kind === "native-cfg"));
});

test("rejects comparison thresholds changed after owner precommit", async () => {
  const fixture = await buildFixture();
  fixture.document.comparisons[0].targetMax = 4;
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /differs from the signed protection policy/);
});

test("rejects omission or tampering of mandatory adversarial evidence", async () => {
  const fixture = await buildFixture();
  fixture.document.adversarialProbes = [];
  await writeJson(fixture.assessment, fixture.document);
  let result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /adversarial runtime probe is required/);

  const fixture2 = await buildFixture();
  await writeFile(path.join(fixture2.directory, "adversarial-runtime.json"), "{}\n");
  result = run(fixture2.assessment, fixture2.trustBundlePath, fixture2.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /hash mismatch/);
});

test("rejects an assessment without patched-client server authorization evidence", async () => {
  const fixture = await buildFixture();
  delete fixture.document.regressions.serverAuthorization;
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /regressions fields must be exactly/);
});

test("rejects the old handwritten regression placeholder", async () => {
  const fixture = await buildFixture();
  const placeholder = Buffer.from("passed\n");
  await writeFile(path.join(fixture.directory, "functional.txt"), placeholder);
  fixture.document.regressions.functional = { status: "passed", evidence: "functional.txt", sha256: sha(placeholder) };
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /regressions\.functional fields must be exactly/);
});

test("rejects omission of the pinned public deobfuscator attack", async () => {
  const fixture = await buildFixture();
  fixture.document.adversarialProbes = fixture.document.adversarialProbes.filter((item) => item.id !== "A-PUBLIC-DEOBFUSCATOR");
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /public-deobfuscator attack is required/);
});

test("rejects omission of the owner holdout behavior attack", async () => {
  const fixture = await buildFixture();
  fixture.document.adversarialProbes = fixture.document.adversarialProbes.filter((item) => item.id !== "A-BEHAVIOR-HOLDOUT");
  await writeJson(fixture.assessment, fixture.document); const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1); assert.match(result.stderr, /owner holdout behavior attack is required/);
});

test("rejects omission or post-report mutation of the mandatory cross-build corpus", async () => {
  let fixture = await buildFixture(); fixture.document.adversarialProbes = fixture.document.adversarialProbes.filter((item) => item.id !== "A-CROSS-BUILD"); await writeJson(fixture.assessment, fixture.document);
  let result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath); assert.equal(result.status, 1); assert.match(result.stderr, /mandatory T1 cross-build alignment attack/);
  fixture = await buildFixture(); const declaration = fixture.document.adversarialProbes.find((item) => item.id === "A-CROSS-BUILD"); const report = JSON.parse(await readFile(path.join(fixture.directory, declaration.evidence), "utf8")); await writeFile(report.variants[1].path, Buffer.alloc(128, 7));
  result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath); assert.equal(result.status, 1); assert.match(result.stderr, /attestation hash mismatch|does not match a fresh alignment analysis|duplicate bytes|no analyzable/);
});

test("rejects a public-deobfuscator package changed after its report", async () => {
  const fixture = await buildFixture();
  await writeFile(path.join(fixture.directory, "webcrack-package", "index.js"), "export const fixture = false;\n");
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /public deobfuscator entry digest no longer matches/);
});

test("does not overclaim: recovery above the declared attacker tier remains a residual risk, not a failed lower-tier claim", async () => {
  const fixture = await buildFixture({ comparisonTier: "T1" });
  fixture.adversarialReport.status = "recovered";
  fixture.adversarialReport.canaries.recovered = 1;
  fixture.adversarialReport.canaries.recoveredSha256 = [sha(Buffer.from("runtime-secret"))];
  const reportSha256 = await writeJson(path.join(fixture.directory, "adversarial-runtime.json"), fixture.adversarialReport);
  fixture.document.adversarialProbes[0].reportSha256 = reportSha256;
  Object.assign(fixture.document.adversarialProbes[0], await fixture.attest(reportSha256, fixture.adversarialReport.artifact.sha256, "adversarial-probe", "adversarial-runtime.attestation.json"));
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).adversarialProbes.find((item) => item.id === "A-VM-RUNTIME").status, "recovered");
});

test("rejects forged or untrusted patched-client server authorization receipts", async () => {
  const fixture = await buildFixture();
  const evidencePath = path.join(fixture.directory, "server-authorization.json");
  const envelope = JSON.parse(await readFile(evidencePath, "utf8"));
  envelope.signature = `${envelope.signature.slice(0, -2)}AA`;
  fixture.document.regressions.serverAuthorization.sha256 = await writeJson(evidencePath, envelope);
  await writeJson(fixture.assessment, fixture.document);
  let result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /signature is invalid/);

  const fixture2 = await buildFixture();
  const { publicKey } = generateKeyPairSync("ed25519");
  const untrusted = path.join(fixture2.directory, "untrusted.pem");
  await writeFile(untrusted, publicKey.export({ type: "spki", format: "pem" }));
  result = run(fixture2.assessment, fixture2.trustBundlePath, untrusted);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /root key is not pinned/);
});

test("rejects a valid server signer substituting a harmless action for the owner-approved privileged action", async () => {
  const fixture = await buildFixture();
  const item = fixture.document.regressions.serverAuthorization;
  const transcriptPath = path.join(fixture.directory, item.transcript);
  const transcript = JSON.parse(await readFile(transcriptPath, "utf8"));
  transcript.action = "health.check";
  item.transcriptSha256 = await writeJson(transcriptPath, transcript);
  const evidencePath = path.join(fixture.directory, item.evidence);
  const envelope = JSON.parse(await readFile(evidencePath, "utf8"));
  const payload = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
  payload.action = transcript.action;
  payload.transcriptSha256 = item.transcriptSha256;
  const payloadBytes = Buffer.from(JSON.stringify(payload));
  envelope.payload = payloadBytes.toString("base64");
  envelope.signature = sign(null, Buffer.concat([Buffer.from("rea-hardening-server-authorization/v2\0"), payloadBytes]), fixture.serverAuthPrivateKey).toString("base64");
  item.sha256 = await writeJson(evidencePath, envelope);
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /action differs from owner policy/);
});

test("rejects a rewritten raw server transcript even when the assessment digest is updated", async () => {
  const fixture = await buildFixture();
  const item = fixture.document.regressions.serverAuthorization;
  const transcriptPath = path.join(fixture.directory, item.transcript);
  const transcript = JSON.parse(await readFile(transcriptPath, "utf8"));
  transcript.scenarios[1].serverDecision = "allowed";
  item.transcriptSha256 = await writeJson(transcriptPath, transcript);
  await writeJson(fixture.assessment, fixture.document);
  const result = run(fixture.assessment, fixture.trustBundlePath, fixture.trustRootPublicKeyPath);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /transcript binding mismatch/);
});

test("signs the validated PASS with a separate assessment-gate key", async () => {
  const fixture = await buildFixture();
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePath = path.join(fixture.directory, "assessment-gate-private.pem");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }));
  fixture.trustPayload.roles["assessment-gate"] = [trustEntry(publicKey)];
  await writeJson(fixture.trustBundlePath, createTrustBundleEnvelope(fixture.trustPayload, fixture.trustRootPrivateKey));
  const result = spawnSync(process.execPath, [validator, fixture.assessment, "--trust-bundle", fixture.trustBundlePath, "--trust-root-public-key", fixture.trustRootPublicKeyPath, "--challenge-ledger", fixture.challengeLedger, "--time-authority-client", fixture.timeAuthorityClient, "--gate-private-key", privatePath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const signed = JSON.parse(result.stdout);
  const { gateAttestation, ...core } = signed;
  assert.equal(gateAttestation.format, "rea-hardening-assessment-gate/v1");
  assert.match(core.assessmentSha256, /^[a-f0-9]{64}$/);
  assert.match(core.evidenceRootSha256, /^[a-f0-9]{64}$/);
  assert.equal(core.protectionPolicy.policyId, "fixture-policy-1");
  assert.equal(core.clock.source, "signed-live"); assert.match(core.clock.requestSha256, /^[a-f0-9]{64}$/);
  assert.ok(verify(null, Buffer.concat([Buffer.from("rea-hardening-assessment-gate/v1\0"), Buffer.from(JSON.stringify(core))]), publicKey, Buffer.from(gateAttestation.signature, "base64")));
});
