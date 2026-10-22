#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { lstat, open, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { verifyProtectionPolicyEnvelope } from "./protection-policy.mjs";
import { verifyEvidenceAttestation } from "./evidence-attestation.mjs";
import { verifyRegressionAttestation } from "./regression-attestation.mjs";
import { verifyProtectionTransform } from "./protection-transform.mjs";
import { trustedRoleKey, verifyTrustBundleEnvelope, verifyTrustBundleEnvelopeSignature } from "./trust-bundle.mjs";
import { resolveTrustedTime } from "./trusted-time.mjs";
import { authorizeLiveRemoteTime, consumeTimeAttestation, verifyTimeAttestationEnvelope } from "./time-attestation.mjs";
import { SEMANTIC_SIGNAL_SCORES, semanticCandidates, semanticFingerprint } from "./semantic-recovery.mjs";
import { consumeEvidenceChallenge, verifyEvidenceChallenge } from "./evidence-challenge.mjs";
import { inspectDeliverySurface, validateDeliveryDescriptor } from "./delivery-graph.mjs";
import { analyzeCrossBuildAlignment } from "./probe-cross-build-alignment.mjs";
import { analyzeCrossBuildSemantic } from "./probe-cross-build-semantic.mjs";
import { verifyCrossBuildVariantEnvelope } from "./cross-build-variant-attestation.mjs";

const SCORE_MIN = 0;
const SCORE_MAX = 4;
const PHASES = new Set(["before", "after"]);
const TIERS = new Set(["T0", "T1", "T2", "T3"]);
const TIER_RANK = { T0: 0, T1: 1, T2: 2, T3: 3 };
const SERVER_AUTH_FORMAT = "rea-hardening-server-authorization/v2";
const ASSESSMENT_GATE_FORMAT = "rea-hardening-assessment-gate/v1";

function fail(message) {
  process.stderr.write(`assessment error: ${message}\n`);
  process.exit(1);
}

function exactKeys(value, required, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();
  if (actual.join("\0") !== expected.join("\0")) fail(`${label} fields must be exactly: ${expected.join(", ")}`);
}

function nonempty(value, label) {
  if (typeof value !== "string" || !value.trim()) fail(`${label} must be a nonempty string`);
  return value;
}

function hexDigest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) fail(`${label} must be lowercase SHA-256 hex`);
  return value;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseCli(argv) {
  if (argv.length < 7) fail("usage: validate-assessment.mjs ASSESSMENT.json --trust-bundle SIGNED.json --trust-root-public-key PEM --challenge-ledger DIR --time-authority-client EXECUTABLE [--gate-private-key PEM] [--out NEW.json] [file proof only for diagnostics: --time-attestation SIGNED.json --time-nonce HEX]");
  const assessment = argv[0];
  const options = {};
  const allowed = new Set(["trust-bundle", "trust-root-public-key", "challenge-ledger", "gate-private-key", "out", "now", "time-attestation", "time-nonce", "time-authority-client"]);
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    const name = key?.slice(2);
    if (!key?.startsWith("--") || value === undefined || !allowed.has(name) || options[name] !== undefined) fail("invalid command arguments");
    options[name] = value;
  }
  if (!options["trust-bundle"]) fail("--trust-bundle is required");
  if (!options["trust-root-public-key"]) fail("--trust-root-public-key is required");
  if (!options["challenge-ledger"]) fail("--challenge-ledger is required");
  if ((options["time-attestation"] === undefined) !== (options["time-nonce"] === undefined)) fail("--time-attestation and --time-nonce must be provided together");
  if (options["time-authority-client"] !== undefined && options["time-attestation"] !== undefined) fail("live time authority and file time proof are mutually exclusive");
  if (options["time-nonce"] !== undefined && !/^[a-f0-9]{64}$/.test(options["time-nonce"])) fail("--time-nonce must be 32-byte lowercase hex");
  return { assessment, output: options.out ?? null, trustBundle: options["trust-bundle"], trustRootPublicKey: options["trust-root-public-key"], challengeLedger: options["challenge-ledger"], gatePrivateKey: options["gate-private-key"] ?? null, now: options.now ?? null, timeAttestation: options["time-attestation"] ?? null, timeNonce: options["time-nonce"] ?? null, timeAuthorityClient: options["time-authority-client"] ?? null };
}

function instant(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) fail(`${label} must be canonical ISO-8601`);
  return milliseconds;
}

function safeReference(root, value, label) {
  nonempty(value, label);
  if (path.isAbsolute(value) || value.includes("\0")) fail(`${label} must be a relative path`);
  const resolved = path.resolve(root, value);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) fail(`${label} escapes the assessment directory`);
  return resolved;
}

async function readBoundFile(root, reference, expectedSha256, label) {
  const file = safeReference(root, reference, `${label}.path`);
  const bytes = await readFile(file);
  if (digest(bytes) !== hexDigest(expectedSha256, `${label}.sha256`)) fail(`${label} hash mismatch`);
  return { file, bytes };
}

function envelopeKeyId(bytes, label) {
  let envelope;
  try { envelope = JSON.parse(Buffer.from(bytes).toString("utf8")); }
  catch { fail(`${label} is not valid JSON`); }
  if (!/^[a-f0-9]{64}$/.test(envelope?.keyId ?? "")) fail(`${label} lacks a valid keyId`);
  return envelope.keyId;
}

function roleKeyForEnvelope(trustBundle, role, bytes, label) {
  try { return trustedRoleKey(trustBundle, role, envelopeKeyId(bytes, label)).bytes; }
  catch (error) { fail(error instanceof Error ? error.message : String(error)); }
}

async function artifactDigest(rootValue) {
  const root = await realpath(rootValue);
  if (!(await lstat(root)).isDirectory()) fail("verified artifact must be a directory");
  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      if (entry.isSymbolicLink()) fail(`artifact contains a symlink: ${relative}`);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile()) {
        const bytes = await readFile(absolute);
        files.push({ path: relative, bytes: bytes.length, sha256: digest(bytes) });
      } else fail(`artifact contains unsupported entry: ${relative}`);
    }
  }
  await visit(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { root, sha256: digest(Buffer.from(files.map((item) => `${item.path}\0${item.bytes}\0${item.sha256}`).join("\n"))) };
}

function score(value, label) {
  if (!Number.isInteger(value) || value < SCORE_MIN || value > SCORE_MAX) fail(`${label} must be an integer from 0 to 4`);
  return value;
}

function references(value, label, probes, phase) {
  exactKeys(value, ["probeIds", "score"], label);
  score(value.score, `${label}.score`);
  if (!Array.isArray(value.probeIds) || value.probeIds.length === 0 || value.probeIds.some((item) => typeof item !== "string") || new Set(value.probeIds).size !== value.probeIds.length) fail(`${label}.probeIds must be a nonempty unique string array`);
  for (const id of value.probeIds) {
    const probe = probes.get(id);
    if (!probe) fail(`${label} references unknown probe: ${id}`);
    if (probe.phase !== phase) fail(`${label} references ${probe.phase} probe ${id}, expected ${phase}`);
  }
}

async function verifyChallengeBinding(root, declaration, label, trustBundle, worker, expected, challengeContext, nowValue) {
  const challenge = await readBoundFile(root, declaration.challenge, declaration.challengeSha256, `${label}.challenge`);
  let verified;
  try { verified = verifyEvidenceChallenge(challenge.bytes, roleKeyForEnvelope(trustBundle, "evidence-coordinator", challenge.bytes, `${label}.challenge`), { ...expected, workerKeyId: worker.keyId, evaluationId: challengeContext.evaluationId }, nowValue); }
  catch (error) { fail(error instanceof Error ? `${label}: ${error.message}` : String(error)); }
  if (challengeContext.usedChallengeIds.has(verified.payload.challengeId)) fail(`${label} reuses evidence challenge ${verified.payload.challengeId}`);
  challengeContext.usedChallengeIds.add(verified.payload.challengeId);
  for (const name of ["challengeId", "runnerId", "environmentSha256", "workloadIdentity"]) if (worker.payload[name] !== verified.payload[name]) fail(`${label} worker attestation ${name} differs from its coordinator challenge`);
  if (worker.payload.challengeSha256 !== verified.envelopeSha256 || declaration.challengeSha256 !== verified.envelopeSha256) fail(`${label} worker attestation challenge digest mismatch`);
  if (Date.parse(worker.payload.expiresAt) > Date.parse(verified.payload.expiresAt)) fail(`${label} worker attestation outlives its coordinator challenge`);
  try { challengeContext.consumptionRecords.push(await consumeEvidenceChallenge(challengeContext.ledgerRoot, verified, challengeContext.evaluationId, nowValue)); }
  catch (error) { fail(error instanceof Error ? `${label}: ${error.message}` : String(error)); }
  return verified;
}

async function verifyProbe(root, declaration, index, artifactRoot, trustBundle, allowedWorkerKeyIds, challengeContext, nowValue) {
  const label = `probes[${index}]`;
  exactKeys(declaration, ["attestation", "attestationSha256", "challenge", "challengeSha256", "evidence", "family", "id", "phase", "reportSha256"], label);
  const id = nonempty(declaration.id, `${label}.id`);
  const family = nonempty(declaration.family, `${label}.family`);
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(family)) fail(`${label}.family is invalid`);
  if (!PHASES.has(declaration.phase)) fail(`${label}.phase is invalid`);
  const evidenceDirectory = safeReference(root, declaration.evidence, `${label}.evidence`);
  const probeBytes = await readFile(path.join(evidenceDirectory, "probe.json"));
  if (digest(probeBytes) !== hexDigest(declaration.reportSha256, `${label}.reportSha256`)) fail(`${label} probe report hash mismatch`);
  const report = JSON.parse(probeBytes.toString("utf8"));
  exactKeys(report, ["adapter", "artifact", "artifactIdentity", "evidence", "execution", "invocation", "reasons", "schemaVersion", "status"], `${label}.report`);
  if (report.schemaVersion !== 1 || report.status !== "valid" || report.reasons.length !== 0) fail(`${label} report is not valid evidence`);
  if (report.adapter?.family !== family || typeof report.adapter?.id !== "string" || !/^[a-f0-9]{64}$/.test(report.adapter?.sha256 ?? "")) fail(`${label} adapter identity mismatch`);
  const executable = report.invocation?.executable;
  if (!executable || typeof executable.path !== "string" || !/^[a-f0-9]{64}$/.test(executable.sha256 ?? "")) fail(`${label} executable identity is missing`);
  const currentExecutable = await realpath(executable.path);
  if (digest(await readFile(currentExecutable)) !== executable.sha256) fail(`${label} executable digest no longer matches`);
  let stdoutBytes = null;
  for (const stream of ["stdout", "stderr"]) {
    const metadata = report.evidence?.[stream];
    if (!metadata || metadata.path !== `${stream}.bin` || !Number.isSafeInteger(metadata.bytes) || metadata.bytes < 0 || !/^[a-f0-9]{64}$/.test(metadata.sha256 ?? "")) fail(`${label} has invalid ${stream} metadata`);
    const bytes = await readFile(path.join(evidenceDirectory, metadata.path));
    if (bytes.length !== metadata.bytes || digest(bytes) !== metadata.sha256) fail(`${label} ${stream} evidence was modified`);
    if (stream === "stdout") stdoutBytes = bytes;
  }
  const probeArtifact = await realpath(report.artifact);
  const probeStat = await lstat(probeArtifact);
  let currentProbeSha256;
  if (probeStat.isDirectory()) currentProbeSha256 = (await artifactDigest(probeArtifact)).sha256;
  else if (probeStat.isFile()) currentProbeSha256 = digest(await readFile(probeArtifact));
  else fail(`${label} artifact is not a file or directory`);
  if (!new Set(["file", "directory"]).has(report.artifactIdentity?.kind) || report.artifactIdentity.kind !== (probeStat.isFile() ? "file" : "directory") || report.artifactIdentity.sha256 !== currentProbeSha256) fail(`${label} artifact identity mismatch`);
  const insideRelease = probeArtifact === artifactRoot || probeArtifact.startsWith(`${artifactRoot}${path.sep}`);
  if (declaration.phase === "after" && !insideRelease) fail(`${label} is not bound to the verified release artifact`);
  if (declaration.phase === "before" && insideRelease) fail(`${label} reuses the hardened artifact as its baseline`);
  const attestation = await readBoundFile(root, declaration.attestation, declaration.attestationSha256, `${label}.attestation`);
  let worker;
  try { worker = verifyEvidenceAttestation(attestation.bytes, roleKeyForEnvelope(trustBundle, "evidence-worker", attestation.bytes, `${label}.attestation`), { kind: "analyzer-probe", reportSha256: declaration.reportSha256, artifactSha256: currentProbeSha256 }, nowValue); }
  catch (error) { fail(error instanceof Error ? `${label}: ${error.message}` : String(error)); }
  if (!allowedWorkerKeyIds.has(worker.keyId)) fail(`${label} evidence worker is not approved by the protection policy`);
  const challenge = await verifyChallengeBinding(root, declaration, label, trustBundle, worker, { product: challengeContext.product, policySha256: challengeContext.policySha256, artifactSha256: currentProbeSha256, kind: "analyzer-probe" }, challengeContext, nowValue);
  return { id, family, phase: declaration.phase, adapterId: report.adapter.id, adapterSha256: report.adapter.sha256, executableSha256: executable.sha256, stdoutBytes, workerKeyId: worker.keyId, runnerId: challenge.payload.runnerId, environmentSha256: challenge.payload.environmentSha256, workloadIdentity: challenge.payload.workloadIdentity };
}

async function verifyAdversarialProbe(root, declaration, index, artifactRoot, expectedFunctionIds, trustBundle, allowedWorkerKeyIds, challengeContext, nowValue) {
  const label = `adversarialProbes[${index}]`;
  exactKeys(declaration, ["attestation", "attestationSha256", "challenge", "challengeSha256", "comparisonIds", "evidence", "id", "reportSha256", "tier"], label);
  const id = nonempty(declaration.id, `${label}.id`);
  if (!TIERS.has(declaration.tier)) fail(`${label}.tier must be T0, T1, T2, or T3`);
  if (!Array.isArray(declaration.comparisonIds) || declaration.comparisonIds.length === 0 || declaration.comparisonIds.some((item) => typeof item !== "string" || !item.trim()) || new Set(declaration.comparisonIds).size !== declaration.comparisonIds.length) fail(`${label}.comparisonIds must be a nonempty unique string array`);
  const bound = await readBoundFile(root, declaration.evidence, declaration.reportSha256, label);
  const report = JSON.parse(bound.bytes.toString("utf8"));
  const supported = new Set(["anti-rea-vm-runtime-hook", "anti-rea-vm-public-deobfuscator", "anti-rea-behavior-holdout", "anti-rea-cross-build-alignment", "anti-rea-cross-build-semantic"]);
  if (!supported.has(report?.probe)) fail(`${label} is not a supported Anti-REA attack report`);
  if (report.probe === "anti-rea-behavior-holdout") {
    exactKeys(report, ["artifact", "candidate", "corpus", "coverage", "executionError", "limitations", "probe", "reference", "runtime", "schemaVersion", "status"], `${label}.report`);
    if (report.schemaVersion !== 1 || !new Set(["recovered", "not-recovered"]).has(report.status) || report.executionError !== null) fail(`${label} behavior holdout report is invalid or inconclusive`);
    exactKeys(report.coverage, ["candidateCases", "complete", "expectedCases", "referenceCases"], `${label}.report.coverage`);
    if (report.coverage.complete !== true || !Number.isSafeInteger(report.coverage.expectedCases) || report.coverage.expectedCases < 1 || report.coverage.expectedCases > 256 || report.coverage.referenceCases !== report.coverage.expectedCases || report.coverage.candidateCases !== report.coverage.expectedCases) fail(`${label} behavior holdout coverage is incomplete`);
    exactKeys(report.corpus, ["cases", "inputSha256", "sha256"], `${label}.report.corpus`);
    if (report.corpus.cases !== report.coverage.expectedCases || !/^[a-f0-9]{64}$/.test(report.corpus.sha256 ?? "") || !Array.isArray(report.corpus.inputSha256) || report.corpus.inputSha256.length !== report.corpus.cases || report.corpus.inputSha256.some((item) => !/^[a-f0-9]{64}$/.test(item)) || new Set(report.corpus.inputSha256).size !== report.corpus.inputSha256.length) fail(`${label} behavior corpus identity is invalid`);
    exactKeys(report.artifact, ["path", "sha256"], `${label}.report.artifact`);
    const target = await realpath(report.artifact.path); const targetStat = await lstat(target);
    if (!targetStat.isFile() || (target !== artifactRoot && !target.startsWith(`${artifactRoot}${path.sep}`))) fail(`${label} is not bound to a file in the verified release artifact`);
    const currentSha256 = digest(await readFile(target)); if (currentSha256 !== hexDigest(report.artifact.sha256, `${label}.report.artifact.sha256`)) fail(`${label} target artifact changed after the behavior probe`);
    for (const name of ["runtime", "reference", "candidate"]) {
      const item = report[name]; const fields = name === "runtime" ? ["path", "sha256"] : ["behavior", "path", "sha256"];
      exactKeys(item, fields, `${label}.report.${name}`); const current = await realpath(item.path);
      if (digest(await readFile(current)) !== hexDigest(item.sha256, `${label}.report.${name}.sha256`)) fail(`${label} behavior ${name} identity no longer matches`);
    }
    let referenceBehaviorSha256; let candidateBehaviorSha256;
    try { referenceBehaviorSha256 = semanticFingerprint("behavior-vector", report.reference.behavior); candidateBehaviorSha256 = semanticFingerprint("behavior-vector", report.candidate.behavior); }
    catch (error) { fail(`${label} behavior vector is invalid: ${error instanceof Error ? error.message : String(error)}`); }
    if ((report.status === "recovered") !== (referenceBehaviorSha256 === candidateBehaviorSha256)) fail(`${label} behavior status contradicts the measured vectors`);
    if (!Array.isArray(report.limitations) || report.limitations.some((item) => typeof item !== "string" || !item.trim())) fail(`${label} behavior limitations are invalid`);
    const attestation = await readBoundFile(root, declaration.attestation, declaration.attestationSha256, `${label}.attestation`); let worker;
    try { worker = verifyEvidenceAttestation(attestation.bytes, roleKeyForEnvelope(trustBundle, "evidence-worker", attestation.bytes, `${label}.attestation`), { kind: "adversarial-probe", reportSha256: declaration.reportSha256, artifactSha256: currentSha256 }, nowValue); }
    catch (error) { fail(error instanceof Error ? `${label}: ${error.message}` : String(error)); }
    if (!allowedWorkerKeyIds.has(worker.keyId)) fail(`${label} evidence worker is not approved by the protection policy`);
    const challenge = await verifyChallengeBinding(root, declaration, label, trustBundle, worker, { product: challengeContext.product, policySha256: challengeContext.policySha256, artifactSha256: currentSha256, kind: "adversarial-probe" }, challengeContext, nowValue);
    return { id, probe: report.probe, tier: declaration.tier, comparisonIds: declaration.comparisonIds, status: report.status, recovered: report.coverage.candidateCases, suppliedSha256: null, referenceBehaviorSha256, candidateBehaviorSha256, workerKeyId: worker.keyId, runnerId: challenge.payload.runnerId, environmentSha256: challenge.payload.environmentSha256, workloadIdentity: challenge.payload.workloadIdentity };
  }
  if (report.probe === "anti-rea-cross-build-semantic") {
    if (declaration.tier !== "T1") fail(`${label} semantic cross-build attack must run at T1`);
    exactKeys(report, ["analysis", "artifact", "coverage", "executionError", "limitations", "probe", "schemaVersion", "status", "thresholds", "tool", "variants"], `${label}.report`);
    if (report.schemaVersion !== 1 || !new Set(["recovered", "not-recovered"]).has(report.status) || report.executionError !== null) fail(`${label} semantic cross-build report is invalid or inconclusive`);
    exactKeys(report.artifact, ["path", "sha256"], `${label}.report.artifact`); const target = await realpath(report.artifact.path); const targetStat = await lstat(target);
    if (!targetStat.isFile() || (target !== artifactRoot && !target.startsWith(`${artifactRoot}${path.sep}`)) || digest(await readFile(target)) !== hexDigest(report.artifact.sha256, `${label}.report.artifact.sha256`)) fail(`${label} semantic target is not the verified release file`);
    exactKeys(report.coverage, ["complete", "expectedVariants", "observedVariants"], `${label}.report.coverage`);
    if (report.coverage.complete !== true || !Number.isSafeInteger(report.coverage.expectedVariants) || report.coverage.expectedVariants < 20 || report.coverage.expectedVariants > 64 || report.coverage.observedVariants !== report.coverage.expectedVariants || !Array.isArray(report.variants) || report.variants.length !== report.coverage.expectedVariants) fail(`${label} semantic cross-build coverage is incomplete`);
    exactKeys(report.thresholds, ["consensusRatio", "maximumPairwiseFeatureJaccard"], `${label}.report.thresholds`); if (report.thresholds.consensusRatio !== 0.8 || report.thresholds.maximumPairwiseFeatureJaccard !== 0.7) fail(`${label} semantic thresholds were weakened`);
    exactKeys(report.analysis, ["alignedVariants", "maximumPairwiseFeatureJaccard", "minSupport", "targetFeatureSetSha256", "targetFeatures", "targetFingerprint"], `${label}.report.analysis`);
    if (!Number.isSafeInteger(report.analysis.alignedVariants) || report.analysis.alignedVariants < 1 || report.analysis.alignedVariants > report.coverage.expectedVariants || !Number.isSafeInteger(report.analysis.minSupport) || report.analysis.minSupport !== Math.ceil(report.coverage.expectedVariants * 0.8) || !Number.isSafeInteger(report.analysis.targetFeatures) || report.analysis.targetFeatures < 1 || !/^[a-f0-9]{64}$/.test(report.analysis.targetFingerprint ?? "") || !/^[a-f0-9]{64}$/.test(report.analysis.targetFeatureSetSha256 ?? "") || typeof report.analysis.maximumPairwiseFeatureJaccard !== "number" || report.analysis.maximumPairwiseFeatureJaccard < 0 || report.analysis.maximumPairwiseFeatureJaccard > 1) fail(`${label} semantic analysis is invalid`);
    exactKeys(report.tool, ["adapter", "executable", "family"], `${label}.report.tool`); if (report.tool.family !== "semantic-ir") fail(`${label} semantic tool family is invalid`);
    for (const name of ["adapter", "executable"]) { exactKeys(report.tool[name], ["path", "sha256"], `${label}.report.tool.${name}`); if (!/^[a-f0-9]{64}$/.test(report.tool[name].sha256 ?? "")) fail(`${label} semantic ${name} identity is invalid`); }
    const adapterPath = await realpath(report.tool.adapter.path); const executablePath = await realpath(report.tool.executable.path);
    if (digest(await readFile(adapterPath)) !== report.tool.adapter.sha256 || digest(await readFile(executablePath)) !== report.tool.executable.sha256) fail(`${label} semantic tool changed after analysis`);
    const approvedAnalyzer = challengeContext.policy.analyzers.find((item) => item.family === "semantic-ir"); if (!approvedAnalyzer || approvedAnalyzer.adapterSha256 !== report.tool.adapter.sha256 || approvedAnalyzer.executableSha256 !== report.tool.executable.sha256) fail(`${label} semantic tool is not owner-approved`);
    const variantInputs = []; const variantRunIds = new Set(); const seedCommitments = new Set();
    for (const [variantIndex, variant] of report.variants.entries()) {
      exactKeys(variant, ["attestation", "bytes", "edgeCount", "featureCount", "featureSetSha256", "fingerprint", "irSha256", "nodeCount", "path", "sha256"], `${label}.report.variants[${variantIndex}]`); exactKeys(variant.attestation, ["path", "sha256"], `${label}.report.variants[${variantIndex}].attestation`);
      if (!Number.isSafeInteger(variant.bytes) || variant.bytes < 1 || !Number.isSafeInteger(variant.nodeCount) || variant.nodeCount < 2 || !Number.isSafeInteger(variant.edgeCount) || variant.edgeCount < 1 || !Number.isSafeInteger(variant.featureCount) || variant.featureCount < 1 || [variant.sha256, variant.attestation.sha256, variant.irSha256, variant.fingerprint, variant.featureSetSha256].some((item) => !/^[a-f0-9]{64}$/.test(item ?? ""))) fail(`${label}.report.variants[${variantIndex}] semantic identity is invalid`);
      const attestationPath = await realpath(variant.attestation.path); const attestationBytes = await readFile(attestationPath); if (digest(attestationBytes) !== variant.attestation.sha256) fail(`${label}.report.variants[${variantIndex}] attestation hash mismatch`);
      const source = challengeContext.policy.productSource; let verifiedVariant;
      try { verifiedVariant = verifyCrossBuildVariantEnvelope(attestationBytes, roleKeyForEnvelope(trustBundle, "product-builder", attestationBytes, `${label}.report.variants[${variantIndex}].attestation`), { product: challengeContext.product, policySha256: challengeContext.policySha256, repositoryUri: source.repositoryUri, commit: source.commit, tree: source.tree, buildDefinitionSha256: source.buildDefinitionSha256, builderId: source.builderId, builderEnvironmentSha256: source.builderEnvironmentSha256, regionSha256: variant.sha256, variantOrdinal: variantIndex }, nowValue); }
      catch (error) { fail(`${label}.report.variants[${variantIndex}]: ${error instanceof Error ? error.message : String(error)}`); }
      if (Date.parse(verifiedVariant.payload.issuedAt) < Date.parse(challengeContext.policy.issuedAt) || Date.parse(verifiedVariant.payload.expiresAt) > Date.parse(challengeContext.policy.expiresAt) || verifiedVariant.keyId !== source.builderKeyId || variantRunIds.has(verifiedVariant.payload.runId) || seedCommitments.has(verifiedVariant.payload.diversitySeedCommitment)) fail(`${label}.report.variants[${variantIndex}] builder identity, validity, run ID, or seed is invalid`);
      variantRunIds.add(verifiedVariant.payload.runId); seedCommitments.add(verifiedVariant.payload.diversitySeedCommitment); variantInputs.push({ path: variant.path, attestation: attestationPath });
    }
    let recomputed; try { recomputed = await analyzeCrossBuildSemantic(target, variantInputs, adapterPath); } catch (error) { fail(`${label}: ${error instanceof Error ? error.message : String(error)}`); }
    if (JSON.stringify(recomputed) !== JSON.stringify(report)) fail(`${label} semantic report does not match a fresh extraction and alignment`);
    const attestation = await readBoundFile(root, declaration.attestation, declaration.attestationSha256, `${label}.attestation`); let worker;
    try { worker = verifyEvidenceAttestation(attestation.bytes, roleKeyForEnvelope(trustBundle, "evidence-worker", attestation.bytes, `${label}.attestation`), { kind: "adversarial-probe", reportSha256: declaration.reportSha256, artifactSha256: report.artifact.sha256 }, nowValue); } catch (error) { fail(error instanceof Error ? `${label}: ${error.message}` : String(error)); }
    if (!allowedWorkerKeyIds.has(worker.keyId)) fail(`${label} evidence worker is not approved by the protection policy`);
    const challenge = await verifyChallengeBinding(root, declaration, label, trustBundle, worker, { product: challengeContext.product, policySha256: challengeContext.policySha256, artifactSha256: report.artifact.sha256, kind: "adversarial-probe" }, challengeContext, nowValue);
    const aligned = Math.max(report.analysis.alignedVariants, Math.ceil(report.analysis.maximumPairwiseFeatureJaccard * report.coverage.expectedVariants));
    return { id, probe: report.probe, tier: declaration.tier, comparisonIds: declaration.comparisonIds, status: report.status, recovered: aligned, suppliedSha256: null, workerKeyId: worker.keyId, runnerId: challenge.payload.runnerId, environmentSha256: challenge.payload.environmentSha256, workloadIdentity: challenge.payload.workloadIdentity };
  }
  if (report.probe === "anti-rea-cross-build-alignment") {
    if (declaration.tier !== "T1") fail(`${label} cross-build alignment must run at T1`);
    exactKeys(report, ["analysis", "artifact", "coverage", "executionError", "limitations", "probe", "schemaVersion", "status", "thresholds", "variants"], `${label}.report`);
    if (report.schemaVersion !== 1 || !new Set(["recovered", "not-recovered"]).has(report.status) || report.executionError !== null) fail(`${label} cross-build report is invalid or inconclusive`);
    exactKeys(report.artifact, ["path", "sha256"], `${label}.report.artifact`); const target = await realpath(report.artifact.path); const targetStat = await lstat(target);
    if (!targetStat.isFile() || (target !== artifactRoot && !target.startsWith(`${artifactRoot}${path.sep}`)) || digest(await readFile(target)) !== hexDigest(report.artifact.sha256, `${label}.report.artifact.sha256`)) fail(`${label} cross-build target is not the verified release file`);
    exactKeys(report.coverage, ["complete", "expectedVariants", "observedVariants"], `${label}.report.coverage`);
    if (report.coverage.complete !== true || !Number.isSafeInteger(report.coverage.expectedVariants) || report.coverage.expectedVariants < 20 || report.coverage.expectedVariants > 64 || report.coverage.observedVariants !== report.coverage.expectedVariants || !Array.isArray(report.variants) || report.variants.length !== report.coverage.expectedVariants) fail(`${label} cross-build coverage is incomplete`);
    exactKeys(report.thresholds, ["maximumPairwiseJaccard", "maximumStableByteRatio"], `${label}.report.thresholds`);
    if (report.thresholds.maximumStableByteRatio !== 0.1 || report.thresholds.maximumPairwiseJaccard !== 0.25) fail(`${label} cross-build thresholds were weakened`);
    exactKeys(report.analysis, ["maximumPairwiseJaccard", "minSupport", "stableByteRatio", "stableWindowSetSha256", "stableWindows", "strideBytes", "targetWindows", "windowBytes"], `${label}.report.analysis`);
    if (!/^[a-f0-9]{64}$/.test(report.analysis.stableWindowSetSha256 ?? "") || !Number.isSafeInteger(report.analysis.stableWindows) || !Number.isSafeInteger(report.analysis.targetWindows) || report.analysis.stableWindows < 0 || report.analysis.targetWindows < 1 || report.analysis.stableWindows > report.analysis.targetWindows) fail(`${label} cross-build analysis is invalid`);
    const variantInputs = []; const variantRunIds = new Set(); const seedCommitments = new Set();
    for (const [variantIndex, variant] of report.variants.entries()) {
      exactKeys(variant, ["attestation", "bytes", "path", "sha256"], `${label}.report.variants[${variantIndex}]`); exactKeys(variant.attestation, ["path", "sha256"], `${label}.report.variants[${variantIndex}].attestation`);
      if (!Number.isSafeInteger(variant.bytes) || variant.bytes < 32 || !/^[a-f0-9]{64}$/.test(variant.sha256 ?? "") || !/^[a-f0-9]{64}$/.test(variant.attestation.sha256 ?? "")) fail(`${label}.report.variants[${variantIndex}] identity is invalid`);
      const attestationPath = await realpath(variant.attestation.path); const attestationBytes = await readFile(attestationPath); if (digest(attestationBytes) !== variant.attestation.sha256) fail(`${label}.report.variants[${variantIndex}] attestation hash mismatch`);
      const source = challengeContext.policy.productSource; let verifiedVariant;
      try { verifiedVariant = verifyCrossBuildVariantEnvelope(attestationBytes, roleKeyForEnvelope(trustBundle, "product-builder", attestationBytes, `${label}.report.variants[${variantIndex}].attestation`), { product: challengeContext.product, policySha256: challengeContext.policySha256, repositoryUri: source.repositoryUri, commit: source.commit, tree: source.tree, buildDefinitionSha256: source.buildDefinitionSha256, builderId: source.builderId, builderEnvironmentSha256: source.builderEnvironmentSha256, regionSha256: variant.sha256, variantOrdinal: variantIndex }, nowValue); }
      catch (error) { fail(`${label}.report.variants[${variantIndex}]: ${error instanceof Error ? error.message : String(error)}`); }
      if (Date.parse(verifiedVariant.payload.issuedAt) < Date.parse(challengeContext.policy.issuedAt) || Date.parse(verifiedVariant.payload.expiresAt) > Date.parse(challengeContext.policy.expiresAt)) fail(`${label}.report.variants[${variantIndex}] attestation is outside the owner policy validity window`);
      if (verifiedVariant.keyId !== source.builderKeyId || variantRunIds.has(verifiedVariant.payload.runId) || seedCommitments.has(verifiedVariant.payload.diversitySeedCommitment)) fail(`${label}.report.variants[${variantIndex}] builder identity, run ID, or diversity seed is invalid or duplicate`);
      variantRunIds.add(verifiedVariant.payload.runId); seedCommitments.add(verifiedVariant.payload.diversitySeedCommitment); variantInputs.push({ path: variant.path, attestation: attestationPath });
    }
    let recomputed; try { recomputed = await analyzeCrossBuildAlignment(target, variantInputs); } catch (error) { fail(`${label}: ${error instanceof Error ? error.message : String(error)}`); }
    if (JSON.stringify(recomputed) !== JSON.stringify(report)) fail(`${label} cross-build report does not match a fresh alignment analysis`);
    const attestation = await readBoundFile(root, declaration.attestation, declaration.attestationSha256, `${label}.attestation`); let worker;
    try { worker = verifyEvidenceAttestation(attestation.bytes, roleKeyForEnvelope(trustBundle, "evidence-worker", attestation.bytes, `${label}.attestation`), { kind: "adversarial-probe", reportSha256: declaration.reportSha256, artifactSha256: report.artifact.sha256 }, nowValue); }
    catch (error) { fail(error instanceof Error ? `${label}: ${error.message}` : String(error)); }
    if (!allowedWorkerKeyIds.has(worker.keyId)) fail(`${label} evidence worker is not approved by the protection policy`);
    const challenge = await verifyChallengeBinding(root, declaration, label, trustBundle, worker, { product: challengeContext.product, policySha256: challengeContext.policySha256, artifactSha256: report.artifact.sha256, kind: "adversarial-probe" }, challengeContext, nowValue);
    const alignedWindows = Math.max(report.analysis.stableWindows, Math.ceil(report.analysis.maximumPairwiseJaccard * report.analysis.targetWindows));
    return { id, probe: report.probe, tier: declaration.tier, comparisonIds: declaration.comparisonIds, status: report.status, recovered: alignedWindows, suppliedSha256: null, workerKeyId: worker.keyId, runnerId: challenge.payload.runnerId, environmentSha256: challenge.payload.environmentSha256, workloadIdentity: challenge.payload.workloadIdentity };
  }
  const reportFields = ["artifact", "canaries", "coverage", "decodedPrograms", "decodedTexts", "executionError", "limitations", "probe", "schemaVersion", "status"];
  if (report.probe === "anti-rea-vm-runtime-hook") reportFields.push("boundaryCoverage");
  if (report.probe === "anti-rea-vm-public-deobfuscator") reportFields.push("recognizedEnvelopes", "tool");
  exactKeys(report, reportFields, `${label}.report`);
  if (report.schemaVersion !== (report.probe === "anti-rea-vm-runtime-hook" ? 2 : 1)) fail(`${label} attack report schema is unsupported`);
  if (!new Set(["recovered", "not-recovered"]).has(report.status) || report.executionError !== null) fail(`${label} report is invalid or inconclusive`);
  exactKeys(report.coverage, ["complete", "expectedFunctionIds", "observedFunctionIds"], `${label}.report.coverage`);
  for (const name of ["expectedFunctionIds", "observedFunctionIds"]) if (!Array.isArray(report.coverage[name]) || report.coverage[name].some((item) => !/^[a-f0-9]{64}$/.test(item)) || new Set(report.coverage[name]).size !== report.coverage[name].length || JSON.stringify([...report.coverage[name]].sort()) !== JSON.stringify(report.coverage[name])) fail(`${label}.report.coverage.${name} is invalid`);
  if (report.coverage.complete !== true || JSON.stringify(report.coverage.expectedFunctionIds) !== JSON.stringify(expectedFunctionIds) || JSON.stringify(report.coverage.observedFunctionIds) !== JSON.stringify(expectedFunctionIds)) fail(`${label} does not cover every protected function ID`);
  exactKeys(report.artifact, ["path", "sha256"], `${label}.report.artifact`);
  const target = await realpath(report.artifact.path);
  const targetStat = await lstat(target);
  if (!targetStat.isFile() || (target !== artifactRoot && !target.startsWith(`${artifactRoot}${path.sep}`))) fail(`${label} is not bound to a file in the verified release artifact`);
  const currentSha256 = digest(await readFile(target));
  if (currentSha256 !== hexDigest(report.artifact.sha256, `${label}.report.artifact.sha256`)) fail(`${label} target artifact changed after the attack probe`);
  exactKeys(report.canaries, ["recovered", "recoveredSha256", "supplied", "suppliedSha256"], `${label}.report.canaries`);
  if (!Number.isSafeInteger(report.canaries.supplied) || report.canaries.supplied < 1 || !Number.isSafeInteger(report.canaries.recovered) || report.canaries.recovered < 0 || report.canaries.recovered > report.canaries.supplied) fail(`${label} has invalid canary counts`);
  if (!Array.isArray(report.canaries.recoveredSha256) || report.canaries.recoveredSha256.length !== report.canaries.recovered || report.canaries.recoveredSha256.some((item) => !/^[a-f0-9]{64}$/.test(item))) fail(`${label} has invalid recovered canary identities`);
  if (!Array.isArray(report.canaries.suppliedSha256) || report.canaries.suppliedSha256.length !== report.canaries.supplied || report.canaries.suppliedSha256.some((item) => !/^[a-f0-9]{64}$/.test(item)) || new Set(report.canaries.suppliedSha256).size !== report.canaries.suppliedSha256.length) fail(`${label} has invalid supplied canary identities`);
  if ((report.status === "recovered") !== (report.canaries.recovered > 0)) fail(`${label} status contradicts its recovered canary count`);
  if (!Number.isSafeInteger(report.decodedPrograms) || report.decodedPrograms < 0 || !Number.isSafeInteger(report.decodedTexts) || report.decodedTexts < 0 || !Array.isArray(report.limitations) || report.limitations.some((item) => typeof item !== "string" || !item.trim())) fail(`${label} report metadata is invalid`);
  if (report.probe === "anti-rea-vm-runtime-hook") {
    const boundaryNames = ["base64-decode", "buffer-to-string", "crypto-decipher", "file-read", "ipc-post-message", "json-parse", "network-fetch", "process-output", "structured-clone", "text-decoder", "webassembly-input"];
    exactKeys(report.boundaryCoverage, boundaryNames, `${label}.report.boundaryCoverage`);
    for (const name of boundaryNames) {
      const item = report.boundaryCoverage[name]; exactKeys(item, ["calls", "installed", "observations"], `${label}.report.boundaryCoverage.${name}`);
      if (item.installed !== true || !Number.isSafeInteger(item.calls) || item.calls < 0 || !Number.isSafeInteger(item.observations) || item.observations < 0 || item.observations > item.calls) fail(`${label} runtime boundary ${name} is not fully installed or has invalid counters`);
    }
    if (report.boundaryCoverage["json-parse"].calls < 1 || report.boundaryCoverage["text-decoder"].calls < 1) fail(`${label} did not exercise the protected VM decode boundaries`);
  }
  if (report.probe === "anti-rea-vm-public-deobfuscator") {
    exactKeys(report.tool, ["deobfuscatedSha256", "executable", "name", "node", "package", "version"], `${label}.report.tool`);
    exactKeys(report.tool.executable, ["path", "sha256"], `${label}.report.tool.executable`);
    if (report.tool.name !== "webcrack" || report.tool.version !== "2.16.0" || typeof report.tool.node !== "string" || !/^[a-f0-9]{64}$/.test(report.tool.deobfuscatedSha256 ?? "")) fail(`${label} public deobfuscator identity is invalid`);
    const executable = await realpath(report.tool.executable.path);
    if (digest(await readFile(executable)) !== hexDigest(report.tool.executable.sha256, `${label}.report.tool.executable.sha256`)) fail(`${label} public deobfuscator runtime digest no longer matches`);
    exactKeys(report.tool.package, ["entry", "lockfile", "manifest", "root"], `${label}.report.tool.package`);
    nonempty(report.tool.package.root, `${label}.report.tool.package.root`);
    for (const name of ["entry", "manifest", "lockfile"]) {
      const item = report.tool.package[name];
      exactKeys(item, ["path", "sha256"], `${label}.report.tool.package.${name}`);
      const current = await realpath(item.path);
      if (digest(await readFile(current)) !== hexDigest(item.sha256, `${label}.report.tool.package.${name}.sha256`)) fail(`${label} public deobfuscator ${name} digest no longer matches`);
      const packageRoot = await realpath(report.tool.package.root);
      if (name !== "lockfile" && current !== packageRoot && !current.startsWith(`${packageRoot}${path.sep}`)) fail(`${label} public deobfuscator ${name} is outside its package root`);
    }
    if (!Number.isSafeInteger(report.recognizedEnvelopes) || report.recognizedEnvelopes < 1) fail(`${label} public deobfuscator recognized no VM envelope`);
  }
  const attestation = await readBoundFile(root, declaration.attestation, declaration.attestationSha256, `${label}.attestation`);
  let worker;
  try { worker = verifyEvidenceAttestation(attestation.bytes, roleKeyForEnvelope(trustBundle, "evidence-worker", attestation.bytes, `${label}.attestation`), { kind: "adversarial-probe", reportSha256: declaration.reportSha256, artifactSha256: currentSha256 }, nowValue); }
  catch (error) { fail(error instanceof Error ? `${label}: ${error.message}` : String(error)); }
  if (!allowedWorkerKeyIds.has(worker.keyId)) fail(`${label} evidence worker is not approved by the protection policy`);
  const challenge = await verifyChallengeBinding(root, declaration, label, trustBundle, worker, { product: challengeContext.product, policySha256: challengeContext.policySha256, artifactSha256: currentSha256, kind: "adversarial-probe" }, challengeContext, nowValue);
  return { id, probe: report.probe, tier: declaration.tier, comparisonIds: declaration.comparisonIds, status: report.status, recovered: report.canaries.recovered, suppliedSha256: [...report.canaries.suppliedSha256].sort(), workerKeyId: worker.keyId, runnerId: challenge.payload.runnerId, environmentSha256: challenge.payload.environmentSha256, workloadIdentity: challenge.payload.workloadIdentity };
}

function parseExposurePolicy(bytes) {
  const value = JSON.parse(bytes.toString("utf8"));
  exactKeys(value, ["facts", "schemaVersion"], "exposurePolicy");
  if (value.schemaVersion !== 2 || !Array.isArray(value.facts) || value.facts.length === 0) fail("exposurePolicy is invalid");
  const facts = new Map();
  for (const [index, fact] of value.facts.entries()) {
    exactKeys(fact, ["authoritativeLocation", "canaries", "classification", "clientImplementation", "description", "id", "impact", "recoverySignals", "serverAuthoritative", "tiers"], `exposurePolicy.facts[${index}]`);
    if (typeof fact.id !== "string" || !/^[A-Z][A-Z0-9-]{1,63}$/.test(fact.id) || facts.has(fact.id)) fail(`exposurePolicy.facts[${index}].id is invalid or duplicate`);
    if (!Array.isArray(fact.canaries) || fact.canaries.some((item) => typeof item !== "string" || item.length < 4) || new Set(fact.canaries).size !== fact.canaries.length) fail(`exposurePolicy.facts[${index}].canaries is invalid`);
    if (!Array.isArray(fact.recoverySignals)) fail(`exposurePolicy.facts[${index}].recoverySignals is invalid`);
    const signalIds = new Set();
    for (const [signalIndex, signal] of fact.recoverySignals.entries()) {
      exactKeys(signal, ["id", "kind", "normalizedSha256"], `exposurePolicy.facts[${index}].recoverySignals[${signalIndex}]`);
      if (typeof signal.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(signal.id) || signalIds.has(signal.id) || !(signal.kind in SEMANTIC_SIGNAL_SCORES) || !/^[a-f0-9]{64}$/.test(signal.normalizedSha256 ?? "")) fail(`exposurePolicy.facts[${index}].recoverySignals[${signalIndex}] is invalid or duplicate`);
      signalIds.add(signal.id);
    }
    if (fact.classification === "COST_ONLY" && fact.clientImplementation === true && fact.recoverySignals.length === 0) fail(`exposurePolicy.facts[${index}] has no semantic recovery signals`);
    facts.set(fact.id, fact);
  }
  return facts;
}

function canaryHashesForComparison(policyComparison, exposureFacts) {
  const values = [];
  for (const factId of policyComparison.factIds) {
    const fact = exposureFacts.get(factId);
    if (!fact) fail(`protection policy references missing exposure fact ${factId}`);
    if (fact.classification !== "COST_ONLY" || fact.clientImplementation !== true) fail(`comparison fact ${factId} must be a client COST_ONLY fact`);
    if (fact.canaries.length === 0) fail(`comparison fact ${factId} has no approved canaries`);
    values.push(...fact.canaries);
  }
  return { values, hashes: [...new Set(values.map((item) => digest(Buffer.from(item))))].sort() };
}

function machineExactRecovery(probeIds, probes, canaries) {
  for (const id of probeIds) {
    const output = probes.get(id)?.stdoutBytes;
    if (output && canaries.some((canary) => output.includes(Buffer.from(canary)))) return 4;
  }
  return 0;
}

function semanticSignalsForComparison(policyComparison, exposureFacts) {
  const signals = [];
  for (const factId of policyComparison.factIds) {
    const fact = exposureFacts.get(factId);
    for (const signal of fact.recoverySignals) signals.push({ factId, ...signal, score: SEMANTIC_SIGNAL_SCORES[signal.kind] });
  }
  return signals;
}

function machineSemanticRecovery(probeIds, probes, signals) {
  const available = new Set();
  for (const id of probeIds) {
    const output = probes.get(id)?.stdoutBytes;
    if (output) for (const candidate of semanticCandidates(output)) available.add(`${candidate.kind}:${candidate.normalizedSha256}`);
  }
  const matches = signals.filter((signal) => available.has(`${signal.kind}:${signal.normalizedSha256}`));
  return { score: matches.reduce((maximum, signal) => Math.max(maximum, signal.score), 0), matches: matches.map(({ factId, id, kind, score }) => ({ factId, signalId: id, kind, score })) };
}

async function verifyServerAuthorizationEvidence(bytes, transcriptBytes, transcriptSchemaSha256, trustBundle, artifactSha256, policy, challengeDeclaration, challengeContext, root, nowValue) {
  const envelope = JSON.parse(bytes.toString("utf8"));
  exactKeys(envelope, ["format", "keyId", "payload", "signature"], "regressions.serverAuthorization.envelope");
  if (envelope.format !== SERVER_AUTH_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") fail("server authorization envelope is invalid");
  const publicKey = createPublicKey(roleKeyForEnvelope(trustBundle, "server-authorization", bytes, "regressions.serverAuthorization.envelope"));
  if (publicKey.asymmetricKeyType !== "ed25519") fail("trusted server authorization key must be Ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (digest(publicDer) !== envelope.keyId) fail("server authorization key is not trusted");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${SERVER_AUTH_FORMAT}\0`), payloadBytes]), publicKey, Buffer.from(envelope.signature, "base64"))) fail("server authorization signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  if (!Buffer.from(JSON.stringify(payload)).equals(payloadBytes)) fail("server authorization payload is not canonical");
  exactKeys(payload, ["action", "artifactSha256", "challengeId", "challengeSha256", "channel", "configSha256", "deploymentSha256", "environment", "expiresAt", "issuedAt", "product", "schemaVersion", "transcriptSchemaSha256", "transcriptSha256"], "regressions.serverAuthorization.payload");
  if (payload.schemaVersion !== 2 || payload.artifactSha256 !== artifactSha256 || payload.product !== policy.product) fail("server authorization payload identity is invalid");
  for (const name of ["action", "channel", "environment"]) if (payload[name] !== policy.serverAuthorization[name]) fail(`server authorization ${name} differs from owner policy`);
  for (const name of ["configSha256", "deploymentSha256", "transcriptSchemaSha256"]) if (payload[name] !== policy.serverAuthorization[name]) fail(`server authorization ${name} differs from owner policy`);
  if (payload.transcriptSchemaSha256 !== transcriptSchemaSha256 || payload.transcriptSha256 !== digest(transcriptBytes)) fail("server authorization transcript binding mismatch");
  const now = nowValue === null ? Date.now() : instant(nowValue, "--now");
  const issuedAt = instant(payload.issuedAt, "server authorization issuedAt");
  const expiresAt = instant(payload.expiresAt, "server authorization expiresAt");
  if (issuedAt > now + 5 * 60 * 1000 || expiresAt <= now || expiresAt > issuedAt + 24 * 60 * 60 * 1000) fail("server authorization receipt is stale or has an invalid validity window");
  const challengeFile = await readBoundFile(root, challengeDeclaration.challenge, challengeDeclaration.challengeSha256, "regressions.serverAuthorization.challenge");
  let challenge;
  try { challenge = verifyEvidenceChallenge(challengeFile.bytes, roleKeyForEnvelope(trustBundle, "evidence-coordinator", challengeFile.bytes, "regressions.serverAuthorization.challenge"), { product: policy.product, evaluationId: challengeContext.evaluationId, policySha256: challengeContext.policySha256, artifactSha256, kind: "server-authorization", workerKeyId: envelope.keyId }, nowValue); }
  catch (error) { fail(error instanceof Error ? `regressions.serverAuthorization: ${error.message}` : String(error)); }
  if (payload.challengeId !== challenge.payload.challengeId || payload.challengeSha256 !== challenge.envelopeSha256) fail("server authorization challenge binding mismatch");
  if (challengeContext.usedChallengeIds.has(challenge.payload.challengeId)) fail(`regressions.serverAuthorization reuses evidence challenge ${challenge.payload.challengeId}`);
  challengeContext.usedChallengeIds.add(challenge.payload.challengeId);
  try { challengeContext.consumptionRecords.push(await consumeEvidenceChallenge(challengeContext.ledgerRoot, challenge, challengeContext.evaluationId, nowValue)); }
  catch (error) { fail(error instanceof Error ? `regressions.serverAuthorization: ${error.message}` : String(error)); }
  let transcript;
  try { transcript = JSON.parse(transcriptBytes.toString("utf8")); } catch { fail("server authorization transcript is not valid JSON"); }
  exactKeys(transcript, ["action", "channel", "configSha256", "deploymentSha256", "environment", "product", "scenarios", "schemaVersion"], "regressions.serverAuthorization.transcript");
  if (transcript.schemaVersion !== 1) fail("server authorization transcript schemaVersion is invalid");
  for (const name of ["product", "environment", "channel", "action", "deploymentSha256", "configSha256"]) if (transcript[name] !== payload[name]) fail(`server authorization transcript ${name} mismatch`);
  if (!Array.isArray(transcript.scenarios) || transcript.scenarios.length !== 2) fail("server authorization transcript requires exactly two scenarios");
  const scenarios = new Map();
  for (const [index, scenario] of transcript.scenarios.entries()) {
    exactKeys(scenario, ["clientDecision", "httpStatus", "mutation", "name", "requestSha256", "responseSha256", "serverDecision"], `server authorization scenario[${index}]`);
    if (typeof scenario.name !== "string" || scenarios.has(scenario.name) || !new Set(["allowed", "denied"]).has(scenario.clientDecision) || !new Set(["allowed", "denied"]).has(scenario.serverDecision) || !Number.isSafeInteger(scenario.httpStatus) || typeof scenario.mutation !== "string" || !/^[a-f0-9]{64}$/.test(scenario.requestSha256 ?? "") || !/^[a-f0-9]{64}$/.test(scenario.responseSha256 ?? "")) fail("server authorization scenario is invalid");
    scenarios.set(scenario.name, scenario);
  }
  const legitimate = scenarios.get("legitimate-client");
  const patched = scenarios.get("patched-favorable-client");
  if (!legitimate || legitimate.clientDecision !== "allowed" || legitimate.serverDecision !== "allowed" || legitimate.httpStatus < 200 || legitimate.httpStatus >= 300) fail("legitimate server authorization scenario did not succeed");
  if (!patched || patched.clientDecision !== "allowed" || patched.serverDecision !== "denied" || patched.httpStatus < 400 || !patched.mutation.trim()) fail("patched favorable client was not independently denied by the server");
  return { keyId: envelope.keyId, product: payload.product, environment: payload.environment, channel: payload.channel, action: payload.action, deploymentSha256: payload.deploymentSha256, configSha256: payload.configSha256, transcriptSha256: payload.transcriptSha256, transcriptSchemaSha256: payload.transcriptSchemaSha256, challengeId: payload.challengeId, challengeSha256: payload.challengeSha256, issuedAt: payload.issuedAt, expiresAt: payload.expiresAt };
}

async function verifyRegressionEvidence(root, declaration, name, artifactSha256, trustBundle, allowedWorkerKeyIds, policyIdentity, nowValue) {
  const label = `regressions.${name}`;
  exactKeys(declaration, ["attestation", "attestationSha256", "report", "reportSha256"], label);
  const report = await readBoundFile(root, declaration.report, declaration.reportSha256, `${label}.report`);
  const attestation = await readBoundFile(root, declaration.attestation, declaration.attestationSha256, `${label}.attestation`);
  let verified;
  try {
    verified = await verifyRegressionAttestation(attestation.bytes, report.bytes, roleKeyForEnvelope(trustBundle, "evidence-worker", attestation.bytes, `${label}.attestation`), { artifactSha256, ...policyIdentity }, nowValue);
  } catch (error) {
    fail(error instanceof Error ? `${label}: ${error.message}` : String(error));
  }
  if (!allowedWorkerKeyIds.has(verified.keyId)) fail(`${label} worker is not approved by the protection policy`);
  return { kind: verified.report.kind, workerKeyId: verified.keyId, reportSha256: declaration.reportSha256, attestationSha256: declaration.attestationSha256 };
}

async function main() {
  const cli = parseCli(process.argv.slice(2));
  const assessmentPath = path.resolve(cli.assessment);
  const outputPath = cli.output === null ? null : path.resolve(cli.output);
  if (outputPath === assessmentPath) fail("assessment and output paths must differ");
  const root = await realpath(path.dirname(assessmentPath));
  const assessmentBytes = await readFile(assessmentPath);
  const document = JSON.parse(assessmentBytes.toString("utf8"));
  exactKeys(document, ["adversarialProbes", "artifactVerification", "comparisons", "deliveryGraph", "evaluationId", "exposurePolicy", "negativeControl", "probes", "protectionPolicy", "protectionReceipts", "regressions", "residualRisks", "schemaVersion"], "assessment");
  if (document.schemaVersion !== 6 || typeof document.evaluationId !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}$/.test(document.evaluationId)) fail("unsupported schemaVersion or invalid evaluationId; delivery-graph schemaVersion 6 is required");

  const trustBundleBytes = await readFile(path.resolve(cli.trustBundle)); const trustRootBytes = await readFile(path.resolve(cli.trustRootPublicKey));
  let trustBundle; let clock; let timeConsumption = null;
  try {
    if (cli.timeAuthorityClient !== null) {
      const live = await authorizeLiveRemoteTime({ trustBundleBytes, trustRootPublicKeyBytes: trustRootBytes, product: null, evaluationId: document.evaluationId, authorityClient: cli.timeAuthorityClient, ledgerRoot: cli.challengeLedger });
      clock = live.clock; timeConsumption = live.consumption; trustBundle = live.trustBundle;
    } else if (cli.timeAttestation !== null) {
      const bootstrap = verifyTrustBundleEnvelopeSignature(trustBundleBytes, trustRootBytes); const timeBytes = await readFile(path.resolve(cli.timeAttestation));
      const verifiedTime = verifyTimeAttestationEnvelope(timeBytes, roleKeyForEnvelope(bootstrap, "time-authority", timeBytes, "time attestation"), { product: bootstrap.payload.product, environment: bootstrap.payload.environment, evaluationId: document.evaluationId, nonce: cli.timeNonce });
      clock = verifiedTime.clock; trustBundle = verifyTrustBundleEnvelope(trustBundleBytes, trustRootBytes, { product: bootstrap.payload.product, now: clock.observedAt });
      timeConsumption = await consumeTimeAttestation(cli.challengeLedger, verifiedTime, document.evaluationId);
    } else {
      clock = resolveTrustedTime(cli.now); if (clock.source !== "test-override") throw new Error("production assessment requires --time-authority-client");
      trustBundle = verifyTrustBundleEnvelope(trustBundleBytes, trustRootBytes, { now: clock.observedAt });
    }
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }

  exactKeys(document.protectionPolicy, ["path", "sha256"], "protectionPolicy");
  const signedPolicyFile = await readBoundFile(root, document.protectionPolicy.path, document.protectionPolicy.sha256, "protectionPolicy");
  let signedPolicy;
  try {
    signedPolicy = verifyProtectionPolicyEnvelope(signedPolicyFile.bytes, roleKeyForEnvelope(trustBundle, "protection-policy", signedPolicyFile.bytes, "protectionPolicy"), clock.observedAt);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
  if (trustBundle.payload.product !== signedPolicy.payload.product) fail("trust bundle product does not match the owner protection policy");
  exactKeys(document.exposurePolicy, ["path", "sha256"], "exposurePolicy");
  const exposurePolicyFile = await readBoundFile(root, document.exposurePolicy.path, document.exposurePolicy.sha256, "exposurePolicy");
  if (signedPolicy.payload.exposurePolicySha256 !== document.exposurePolicy.sha256) fail("exposure policy is not the owner-precommitted policy");
  const exposureFacts = parseExposurePolicy(exposurePolicyFile.bytes);
  const policyComparisons = new Map(signedPolicy.payload.comparisons.map((item) => [item.id, item]));
  const allowedWorkerKeyIds = new Set(signedPolicy.payload.evidenceWorkerKeyIds);
  const challengeContext = { product: signedPolicy.payload.product, policy: signedPolicy.payload, policySha256: signedPolicy.envelopeSha256, evaluationId: document.evaluationId, ledgerRoot: cli.challengeLedger, usedChallengeIds: new Set(), consumptionRecords: [] };
  const coveredFacts = new Set(signedPolicy.payload.comparisons.flatMap((item) => item.factIds));
  for (const fact of exposureFacts.values()) {
    if (fact.classification === "COST_ONLY" && fact.clientImplementation === true && !coveredFacts.has(fact.id)) fail(`client COST_ONLY fact ${fact.id} is omitted from the signed comparison policy`);
  }

  exactKeys(document.artifactVerification, ["path", "sha256"], "artifactVerification");
  const artifactVerification = await readBoundFile(root, document.artifactVerification.path, document.artifactVerification.sha256, "artifactVerification");
  const artifactReport = JSON.parse(artifactVerification.bytes.toString("utf8"));
  if (artifactReport?.schemaVersion !== 1 || artifactReport?.status !== "passed" || !/^[a-f0-9]{64}$/.test(artifactReport?.artifactSha256 ?? "")) fail("artifact verification report is not passed");
  const currentArtifact = await artifactDigest(artifactReport.artifact);
  if (currentArtifact.sha256 !== artifactReport.artifactSha256) fail("release artifact changed after verification");

  exactKeys(document.deliveryGraph, ["path", "sha256"], "deliveryGraph");
  const deliveryGraphFile = await readBoundFile(root, document.deliveryGraph.path, document.deliveryGraph.sha256, "deliveryGraph");
  const deliveryGraph = JSON.parse(deliveryGraphFile.bytes.toString("utf8"));
  exactKeys(deliveryGraph, ["descriptorSha256", "schemaVersion", "status", "surfaces"], "deliveryGraph.report");
  if (deliveryGraph.schemaVersion !== 1 || deliveryGraph.status !== "PASS" || !Array.isArray(deliveryGraph.surfaces)) fail("delivery graph report is not PASS");
  const expectedDelivery = signedPolicy.payload.deliverySurfaces.filter((item) => item.disposition === "present");
  if (deliveryGraph.surfaces.length !== expectedDelivery.length) fail("delivery graph omits or adds an owner-precommitted surface");
  const deliveryDescriptor = { schemaVersion: 1, surfaces: deliveryGraph.surfaces.map((item, index) => {
    exactKeys(item, ["audience", "bytes", "files", "findings", "id", "kind", "path", "treeSha256"], `deliveryGraph.report.surfaces[${index}]`);
    return { id: item.id, kind: item.kind, audience: item.audience, path: item.path };
  }) };
  try { validateDeliveryDescriptor(deliveryDescriptor); }
  catch (error) { fail(error instanceof Error ? error.message : String(error)); }
  if (digest(Buffer.from(JSON.stringify(deliveryDescriptor))) !== hexDigest(deliveryGraph.descriptorSha256, "deliveryGraph.report.descriptorSha256")) fail("delivery graph descriptor hash mismatch");
  const expectedById = new Map(expectedDelivery.map((item) => [item.id, item]));
  const deliveryIds = new Set();
  for (const [index, reported] of deliveryGraph.surfaces.entries()) {
    const expected = expectedById.get(reported.id);
    if (!expected || deliveryIds.has(reported.id) || reported.kind !== expected.kind || reported.audience !== expected.audience) fail(`deliveryGraph.report.surfaces[${index}] differs from owner policy`);
    deliveryIds.add(reported.id);
    if (!Array.isArray(reported.findings) || reported.findings.length !== 0) fail(`delivery surface ${reported.id} has security findings`);
    let current;
    try { current = await inspectDeliverySurface(deliveryDescriptor.surfaces[index]); }
    catch (error) { fail(error instanceof Error ? error.message : String(error)); }
    if (JSON.stringify(current) !== JSON.stringify(reported)) fail(`delivery surface ${reported.id} changed after graph verification`);
    if (reported.kind === "release" && reported.path !== currentArtifact.root) fail("release delivery surface is not the verified artifact root");
  }
  if (deliveryIds.size !== expectedById.size) fail("delivery graph does not cover every owner-precommitted surface");
  exactKeys(document.protectionReceipts, ["transform", "virtualization"], "protectionReceipts");
  for (const name of ["virtualization", "transform"]) exactKeys(document.protectionReceipts[name], ["path", "sha256"], `protectionReceipts.${name}`);
  const virtualizationReceipt = await readBoundFile(root, document.protectionReceipts.virtualization.path, document.protectionReceipts.virtualization.sha256, "protectionReceipts.virtualization");
  const transformReceipt = await readBoundFile(root, document.protectionReceipts.transform.path, document.protectionReceipts.transform.sha256, "protectionReceipts.transform");
  let protectedTransform;
  try { protectedTransform = verifyProtectionTransform(signedPolicy.payload.protectionTransform, virtualizationReceipt.bytes, transformReceipt.bytes); }
  catch (error) { fail(error instanceof Error ? error.message : String(error)); }
  const virtualizationOutput = await realpath(protectedTransform.virtualization.output.path);
  if (digest(await readFile(virtualizationOutput)) !== protectedTransform.virtualization.output.sha256) fail("virtualization output changed after receipt creation");
  const transformOutput = await realpath(protectedTransform.transform.output.path);
  if (transformOutput !== currentArtifact.root && !transformOutput.startsWith(`${currentArtifact.root}${path.sep}`)) fail("transform output is outside the verified release artifact");
  if (digest(await readFile(transformOutput)) !== protectedTransform.transform.output.sha256) fail("transform output changed after receipt creation");

  if (!Array.isArray(document.probes) || document.probes.length < 4) fail("at least two before/after analyzer pairs are required");
  const probes = new Map();
  for (const [index, declaration] of document.probes.entries()) {
    const verified = await verifyProbe(root, declaration, index, currentArtifact.root, trustBundle, allowedWorkerKeyIds, challengeContext, clock.observedAt);
    if (probes.has(verified.id)) fail(`duplicate probe id: ${verified.id}`);
    probes.set(verified.id, verified);
  }
  const afterFamilies = new Map();
  for (const probe of probes.values()) {
    if (probe.phase !== "after") continue;
    const identity = `${probe.adapterSha256}:${probe.executableSha256}`;
    if (afterFamilies.has(probe.family) && afterFamilies.get(probe.family) !== identity) fail(`family ${probe.family} changes identity across after probes`);
    afterFamilies.set(probe.family, identity);
  }
  if (afterFamilies.size < 2) fail("at least two trusted analyzer families must have after probes");
  const afterExecutableDigests = [...probes.values()].filter((probe) => probe.phase === "after").map((probe) => probe.executableSha256);
  if (new Set(afterExecutableDigests).size < afterFamilies.size) fail("independent analyzer families resolve to the same executable identity");
  for (const probe of probes.values()) {
    const peer = [...probes.values()].find((item) => item.family === probe.family && item.phase !== probe.phase);
    if (!peer || peer.adapterSha256 !== probe.adapterSha256 || peer.executableSha256 !== probe.executableSha256) fail(`family ${probe.family} lacks a matching before/after tool identity`);
  }
  const trustedAnalyzers = new Map(signedPolicy.payload.analyzers.map((item) => [item.family, item]));
  for (const probe of probes.values()) {
    const trusted = trustedAnalyzers.get(probe.family);
    if (!trusted || trusted.adapterSha256 !== probe.adapterSha256 || trusted.executableSha256 !== probe.executableSha256) fail(`probe ${probe.id} does not match an owner-approved analyzer identity`);
  }

  if (!Array.isArray(document.comparisons) || document.comparisons.length !== policyComparisons.size) fail("assessment comparisons must exactly match the signed protection policy");
  const comparisonIds = new Set();
  const comparisonTiers = new Map();
  const comparisonCanaries = new Map();
  const semanticRecovery = [];
  const failures = [];
  for (const [index, comparison] of document.comparisons.entries()) {
    const label = `comparisons[${index}]`;
    exactKeys(comparison, ["after", "before", "id", "targetMax", "tier"], label);
    const id = nonempty(comparison.id, `${label}.id`);
    if (comparisonIds.has(id)) fail(`duplicate comparison id: ${id}`);
    comparisonIds.add(id);
    const committed = policyComparisons.get(id);
    if (!committed) fail(`${label} is not present in the signed protection policy`);
    if (!TIERS.has(comparison.tier)) fail(`${label}.tier must be T0, T1, T2, or T3`);
    if (TIER_RANK[comparison.tier] > TIER_RANK[signedPolicy.payload.protectionTransform.claimTier]) fail(`${label}.tier exceeds the owner-approved protection transform claim tier`);
    if (comparison.tier !== committed.tier || comparison.targetMax !== committed.targetMax) fail(`${label} tier or targetMax differs from the signed protection policy`);
    comparisonTiers.set(id, comparison.tier);
    const canaries = canaryHashesForComparison(committed, exposureFacts);
    const signals = semanticSignalsForComparison(committed, exposureFacts);
    comparisonCanaries.set(id, canaries);
    score(comparison.targetMax, `${label}.targetMax`);
    references(comparison.before, `${label}.before`, probes, "before");
    references(comparison.after, `${label}.after`, probes, "after");
    for (const family of committed.requiredAnalyzerFamilies) {
      if (!comparison.before.probeIds.some((probeId) => probes.get(probeId)?.family === family) || !comparison.after.probeIds.some((probeId) => probes.get(probeId)?.family === family)) fail(`${label} lacks required before/after analyzer family ${family}`);
    }
    const beforeSemantic = machineSemanticRecovery(comparison.before.probeIds, probes, signals);
    const afterSemantic = machineSemanticRecovery(comparison.after.probeIds, probes, signals);
    const beforeScore = Math.max(comparison.before.score, machineExactRecovery(comparison.before.probeIds, probes, canaries.values), beforeSemantic.score);
    const afterScore = Math.max(comparison.after.score, machineExactRecovery(comparison.after.probeIds, probes, canaries.values), afterSemantic.score);
    semanticRecovery.push({ comparisonId: id, beforeScore: beforeSemantic.score, afterScore: afterSemantic.score, beforeMatches: beforeSemantic.matches, afterMatches: afterSemantic.matches });
    if (afterScore > comparison.targetMax) failures.push(`${id}: evidence-derived after score ${afterScore} exceeds target ${comparison.targetMax}`);
    if (afterScore > beforeScore) failures.push(`${id}: recovery worsened from ${beforeScore} to ${afterScore}`);
    if (beforeScore - afterScore < committed.minimumImprovement) failures.push(`${id}: improvement ${beforeScore - afterScore} is below owner-precommitted minimum ${committed.minimumImprovement}`);
  }
  for (const id of policyComparisons.keys()) if (!comparisonIds.has(id)) fail(`signed comparison ${id} is missing from assessment`);

  if (!Array.isArray(document.adversarialProbes) || document.adversarialProbes.length === 0) fail("at least one evidence-bound adversarial runtime probe is required");
  const adversarialIds = new Set();
  const adversarialProbes = [];
  for (const [index, declaration] of document.adversarialProbes.entries()) {
    const verified = await verifyAdversarialProbe(root, declaration, index, currentArtifact.root, protectedTransform.functionIds, trustBundle, allowedWorkerKeyIds, challengeContext, clock.observedAt);
    if (adversarialIds.has(verified.id)) fail(`duplicate adversarial probe id: ${verified.id}`);
    adversarialIds.add(verified.id);
    for (const comparisonId of verified.comparisonIds) if (!comparisonIds.has(comparisonId)) fail(`adversarial probe ${verified.id} references unknown comparison: ${comparisonId}`);
    if (verified.probe === "anti-rea-behavior-holdout") {
      const expectedBehavior = new Set(verified.comparisonIds.flatMap((comparisonId) => policyComparisons.get(comparisonId).factIds).flatMap((factId) => exposureFacts.get(factId).recoverySignals).filter((signal) => signal.kind === "behavior-vector").map((signal) => signal.normalizedSha256));
      if (expectedBehavior.size === 0 || !expectedBehavior.has(verified.referenceBehaviorSha256)) fail(`adversarial probe ${verified.id} reference behavior is not owner-precommitted for its facts`);
    } else if (!new Set(["anti-rea-cross-build-alignment", "anti-rea-cross-build-semantic"]).has(verified.probe)) {
      const expectedCanaries = [...new Set(verified.comparisonIds.flatMap((comparisonId) => comparisonCanaries.get(comparisonId).hashes))].sort();
      if (JSON.stringify(verified.suppliedSha256) !== JSON.stringify(expectedCanaries)) fail(`adversarial probe ${verified.id} supplied canaries do not match the owner-approved facts`);
    }
    if (verified.status === "recovered") {
      const defeated = verified.comparisonIds.filter((comparisonId) => TIER_RANK[verified.tier] <= TIER_RANK[comparisonTiers.get(comparisonId)]);
      const units = verified.probe === "anti-rea-behavior-holdout" ? "holdout cases" : verified.probe === "anti-rea-cross-build-alignment" ? "aligned windows" : verified.probe === "anti-rea-cross-build-semantic" ? "aligned semantic variants" : "canary facts";
      if (defeated.length > 0) failures.push(`${verified.id}: ${verified.tier} adversarial attack recovered ${verified.recovered} ${units} within claimed tier for ${defeated.join(", ")}`);
    }
    adversarialProbes.push(verified);
  }
  if (!adversarialProbes.some((item) => item.probe === "anti-rea-vm-runtime-hook" && (item.tier === "T2" || item.tier === "T3"))) fail("at least one T2 or T3 adversarial runtime probe is required");
  if (!adversarialProbes.some((item) => item.probe === "anti-rea-vm-public-deobfuscator")) fail("the pinned public-deobfuscator attack is required");
  if (!adversarialProbes.some((item) => item.probe === "anti-rea-behavior-holdout")) fail("the owner holdout behavior attack is required");
  for (const comparisonId of comparisonIds) if (!adversarialProbes.some((item) => item.probe === "anti-rea-cross-build-alignment" && item.comparisonIds.includes(comparisonId))) fail(`comparison ${comparisonId} lacks the mandatory T1 cross-build alignment attack`);
  for (const comparisonId of comparisonIds) if (!adversarialProbes.some((item) => item.probe === "anti-rea-cross-build-semantic" && item.comparisonIds.includes(comparisonId))) fail(`comparison ${comparisonId} lacks the mandatory T1 semantic cross-build attack`);
  for (const [comparisonId, committed] of policyComparisons) {
    for (const requiredProbe of committed.requiredProbes) {
      if (!adversarialProbes.some((item) => item.probe === requiredProbe && item.comparisonIds.includes(comparisonId))) fail(`comparison ${comparisonId} lacks required adversarial probe ${requiredProbe}`);
    }
  }

  exactKeys(document.regressions, ["functional", "performance", "platformSecurity", "serverAuthorization"], "regressions");
  const policyRegressions = new Map(signedPolicy.payload.regressionTests.map((item) => [item.kind, item]));
  const regressionResults = [];
  for (const [name, kind] of [["functional", "functional"], ["performance", "performance"], ["platformSecurity", "platform-security"]]) {
    const policyIdentity = policyRegressions.get(kind);
    if (!policyIdentity) fail(`signed protection policy lacks ${kind} regression identity`);
    regressionResults.push(await verifyRegressionEvidence(root, document.regressions[name], name, currentArtifact.sha256, trustBundle, allowedWorkerKeyIds, policyIdentity, clock.observedAt));
  }
  let serverAuthorization = null;
  const serverItem = document.regressions.serverAuthorization;
  exactKeys(serverItem, ["challenge", "challengeSha256", "evidence", "sha256", "status", "transcript", "transcriptSchema", "transcriptSchemaSha256", "transcriptSha256"], "regressions.serverAuthorization");
  if (serverItem.status !== "passed") failures.push("serverAuthorization regression is not passed");
  const serverEvidence = await readBoundFile(root, serverItem.evidence, serverItem.sha256, "regressions.serverAuthorization");
  const serverTranscript = await readBoundFile(root, serverItem.transcript, serverItem.transcriptSha256, "regressions.serverAuthorization.transcript");
  await readBoundFile(root, serverItem.transcriptSchema, serverItem.transcriptSchemaSha256, "regressions.serverAuthorization.transcriptSchema");
  if (serverEvidence.bytes.length === 0) fail("regressions.serverAuthorization evidence is empty");
  serverAuthorization = await verifyServerAuthorizationEvidence(serverEvidence.bytes, serverTranscript.bytes, serverItem.transcriptSchemaSha256, trustBundle, currentArtifact.sha256, signedPolicy.payload, serverItem, challengeContext, root, clock.observedAt);

  exactKeys(document.negativeControl, ["path", "sha256"], "negativeControl");
  const negative = await readBoundFile(root, document.negativeControl.path, document.negativeControl.sha256, "negativeControl");
  const negativeReport = JSON.parse(negative.bytes.toString("utf8"));
  if (negativeReport?.schemaVersion !== 1 || negativeReport?.status !== "failed" || !Number.isSafeInteger(negativeReport?.summary?.errors) || negativeReport.summary.errors < 1) fail("negative control was not rejected");
  const negativeArtifact = await artifactDigest(negativeReport.artifact);
  if (negativeArtifact.sha256 !== negativeReport.artifactSha256) fail("negative-control artifact changed after verification");

  if (!Array.isArray(document.residualRisks) || document.residualRisks.length === 0 || document.residualRisks.some((item) => typeof item !== "string" || !item.trim())) fail("residualRisks must be a nonempty string array");

  const evidenceRows = [
    ["assessment", digest(assessmentBytes)],
    ["artifactVerification", document.artifactVerification.sha256],
    ["deliveryGraph", document.deliveryGraph.sha256],
    ["exposurePolicy", document.exposurePolicy.sha256],
    ["negativeControl", document.negativeControl.sha256],
    ["protectionPolicy", document.protectionPolicy.sha256],
    ...(timeConsumption === null ? [] : [["time-attestation", clock.attestationSha256], ["time-consumption", timeConsumption.sha256], ...(clock.requestSha256 ? [["time-request", clock.requestSha256]] : [])]),
    ...challengeContext.consumptionRecords.map((item) => [`challenge-consumption:${item.challengeId}`, item.sha256]),
    ["protectionReceipt:virtualization", document.protectionReceipts.virtualization.sha256],
    ["protectionReceipt:transform", document.protectionReceipts.transform.sha256],
    ...document.probes.flatMap((item) => [[`probe:${item.id}:report`, item.reportSha256], [`probe:${item.id}:challenge`, item.challengeSha256], [`probe:${item.id}:attestation`, item.attestationSha256]]),
    ...document.adversarialProbes.flatMap((item) => [[`adversarial:${item.id}:report`, item.reportSha256], [`adversarial:${item.id}:challenge`, item.challengeSha256], [`adversarial:${item.id}:attestation`, item.attestationSha256]]),
    ...regressionResults.flatMap((item) => [[`regression:${item.kind}:report`, item.reportSha256], [`regression:${item.kind}:attestation`, item.attestationSha256]]),
    ["regression:serverAuthorization", serverItem.sha256],
    ["regression:serverAuthorization:transcript", serverItem.transcriptSha256],
    ["regression:serverAuthorization:transcriptSchema", serverItem.transcriptSchemaSha256],
  ].map(([name, sha256]) => `${name}\0${sha256}`).sort();
  const evidenceRootSha256 = digest(Buffer.from(evidenceRows.join("\n")));

  const coreResult = {
    schemaVersion: 8,
    status: failures.length === 0 ? "PASS" : "FAIL",
    artifactSha256: currentArtifact.sha256,
    assessmentSha256: digest(assessmentBytes),
    evaluationId: document.evaluationId,
    evidenceRootSha256,
    clock: new Set(["signed-remote", "signed-live"]).has(clock.source) ? { source: clock.source, observedAt: clock.observedAt, keyId: clock.keyId, attestationSha256: clock.attestationSha256, nonce: clock.nonce, consumptionSha256: timeConsumption.sha256, ...(clock.source === "signed-live" ? { requestSha256: clock.requestSha256, verifierRunId: clock.verifierRunId } : {}) } : { source: clock.source, observedAt: clock.observedAt },
    trustBundle: { bundleId: trustBundle.payload.bundleId, environment: trustBundle.payload.environment, rootKeyId: trustBundle.rootKeyId, sha256: trustBundle.envelopeSha256 },
    protectionPolicy: { policyId: signedPolicy.payload.policyId, product: signedPolicy.payload.product, keyId: signedPolicy.keyId, sha256: signedPolicy.envelopeSha256, exposurePolicySha256: signedPolicy.payload.exposurePolicySha256 },
    deliveryGraph: { sha256: document.deliveryGraph.sha256, surfaces: deliveryGraph.surfaces.map(({ id, kind, audience, treeSha256 }) => ({ id, kind, audience, treeSha256 })) },
    validProbeFamilies: [...afterFamilies.keys()].sort(),
    comparisons: document.comparisons.length,
    semanticRecovery,
    challengeConsumption: challengeContext.consumptionRecords.map(({ challengeId, challengeSha256, evaluationId, consumedAt, sha256 }) => ({ challengeId, challengeSha256, evaluationId, consumedAt, sha256 })),
    adversarialProbes: adversarialProbes.map(({ id, probe, tier, status, recovered }) => ({ id, probe, tier, status, recovered })),
    regressions: regressionResults,
    serverAuthorization,
    failures,
  };
  let gateAttestation = null;
  if (cli.gatePrivateKey !== null) {
    if (clock.source !== "signed-live") fail("assessment gate signing requires live challenged remote time");
    const privateKey = createPrivateKey({ key: await readFile(path.resolve(cli.gatePrivateKey)), passphrase: process.env.REA_ASSESSMENT_GATE_PASSPHRASE });
    if (privateKey.asymmetricKeyType !== "ed25519") fail("assessment gate private key must be Ed25519");
    const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
    try { trustedRoleKey(trustBundle, "assessment-gate", digest(publicDer)); }
    catch (error) { fail(error instanceof Error ? error.message : String(error)); }
    const coreBytes = Buffer.from(JSON.stringify(coreResult));
    gateAttestation = {
      format: ASSESSMENT_GATE_FORMAT,
      keyId: digest(publicDer),
      signature: sign(null, Buffer.concat([Buffer.from(`${ASSESSMENT_GATE_FORMAT}\0`), coreBytes]), privateKey).toString("base64"),
    };
  }
  const result = { ...coreResult, gateAttestation };
  const serialized = `${JSON.stringify(result, null, 2)}\n`;
  if (outputPath !== null) {
    const handle = await open(outputPath, "wx", 0o644);
    try { await handle.writeFile(serialized); } finally { await handle.close(); }
  }
  process.stdout.write(serialized);
  if (failures.length > 0) process.exitCode = 2;
}

main().catch((error) => fail(error instanceof Error ? error.message : String(error)));
