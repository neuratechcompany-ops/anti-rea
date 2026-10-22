#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, open, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { verifyAssessmentGate } from "./assessment-gate.mjs";
import { verifyProtectionPolicyEnvelope } from "./protection-policy.mjs";
import { verifyProductBuildAttestation } from "./product-build-attestation.mjs";
import { verifyProtectionTransform } from "./protection-transform.mjs";
import { trustedRoleKey } from "./trust-bundle.mjs";
import { authorizeLiveRemoteTime, authorizeSignedRemoteTime } from "./time-attestation.mjs";
import { inspectDependencyClosure } from "./dependency-closure.mjs";

const PROTECTOR_ROOT_FILES = new Set(["package.json", "package-lock.json", "SKILL.md"]);
const PROTECTOR_DIRECTORIES = new Set(["adapters", "attacks", "profiles", "references", "scripts", "tests"]);

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: create-provenance.mjs --root PROTECTOR_REPOSITORY --product-root PRODUCT_REPOSITORY --build-definition FILE --virtualization-input FILE --build-attestation FILE --protection-policy FILE --artifact-report FILE --assessment-result FILE --exposure-report FILE --virtualization-report FILE --transform-report FILE --trust-bundle SIGNED.json --trust-root-public-key PEM --time-attestation SIGNED.json --time-nonce HEX --time-ledger DIR --out NEW.json [--allow-dirty true|false]\n");
  process.exit(64);
}

function args(argv) {
  const result = {};
  const allowed = new Set(["root", "product-root", "build-definition", "virtualization-input", "build-attestation", "protection-policy", "artifact-report", "assessment-result", "exposure-report", "virtualization-report", "transform-report", "trust-bundle", "trust-root-public-key", "time-attestation", "time-nonce", "time-authority-client", "time-ledger", "out", "allow-dirty"]);
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    const name = key?.slice(2);
    if (!key?.startsWith("--") || value === undefined || !allowed.has(name) || result[name] !== undefined) usage("invalid arguments");
    result[name] = value;
  }
  for (const name of ["root", "product-root", "build-definition", "virtualization-input", "build-attestation", "protection-policy", "artifact-report", "assessment-result", "exposure-report", "virtualization-report", "transform-report", "trust-bundle", "trust-root-public-key", "time-ledger", "out"]) if (!result[name]) usage(`--${name} is required`);
  if ((result["time-attestation"] === undefined) !== (result["time-nonce"] === undefined) || (result["time-authority-client"] !== undefined) === (result["time-attestation"] !== undefined)) usage("provide exactly one live time authority client or file proof pair");
  if (result["time-nonce"] !== undefined && !/^[a-f0-9]{64}$/.test(result["time-nonce"])) usage("--time-nonce must be 32-byte lowercase hex");
  if (result["allow-dirty"] !== undefined && !new Set(["true", "false"]).has(result["allow-dirty"])) usage("--allow-dirty must be true or false");
  return result;
}

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
async function fileSha256(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

function git(root, values) {
  return execFileSync("git", ["-C", root, ...values], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

async function protectorInventory(root) {
  const files = [];
  async function addFile(absolute, relative) {
    const stat = await lstat(absolute);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`protector inventory entry is not a regular file: ${relative}`);
    files.push({ path: relative.split(path.sep).join("/"), bytes: stat.size, sha256: await fileSha256(absolute) });
  }
  async function visit(directory, relativeDirectory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.isDirectory() && entry.name === "node_modules") continue;
      const absolute = path.join(directory, entry.name);
      const relative = path.join(relativeDirectory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`protector inventory contains a symlink: ${relative}`);
      if (entry.isDirectory()) await visit(absolute, relative);
      else if (entry.isFile()) await addFile(absolute, relative);
      else throw new Error(`protector inventory contains unsupported entry: ${relative}`);
    }
  }
  for (const name of [...PROTECTOR_ROOT_FILES].sort()) await addFile(path.join(root, name), name);
  for (const name of [...PROTECTOR_DIRECTORIES].sort()) await visit(path.join(root, name), name);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, sha256: sha256(Buffer.from(files.map((item) => `${item.path}\0${item.bytes}\0${item.sha256}`).join("\n"))) };
}

async function loadJson(file) {
  const absolute = path.resolve(file);
  const bytes = await readFile(absolute);
  return { absolute, bytes, value: JSON.parse(bytes.toString("utf8")), sha256: sha256(bytes) };
}

function envelopeKeyId(bytes, label) {
  const envelope = JSON.parse(Buffer.from(bytes).toString("utf8"));
  if (!/^[a-f0-9]{64}$/.test(envelope?.keyId ?? "")) throw new Error(`${label} lacks a valid keyId`);
  return envelope.keyId;
}
function roleKeyForEnvelope(trustBundle, role, bytes, label) {
  return trustedRoleKey(trustBundle, role, envelopeKeyId(bytes, label)).bytes;
}

async function main() {
  const options = args(process.argv.slice(2));
  const root = await realpath(options.root);
  const commit = git(root, ["rev-parse", "HEAD"]);
  if (!/^[a-f0-9]{40,64}$/.test(commit)) throw new Error("repository HEAD is invalid");
  const status = git(root, ["status", "--porcelain=v1", "--untracked-files=all"]);
  const dirty = status.length > 0;
  if (dirty && options["allow-dirty"] !== "true") throw new Error("repository is dirty; release provenance requires a clean tree");
  const diff = dirty
    ? execFileSync("git", ["-C", root, "diff", "--binary", "HEAD"], { stdio: ["ignore", "pipe", "pipe"] })
    : Buffer.alloc(0);
  const protector = await protectorInventory(root);
  const dependencies = await inspectDependencyClosure(root);
  const artifact = await loadJson(options["artifact-report"]);
  const assessment = await loadJson(options["assessment-result"]);
  const exposure = await loadJson(options["exposure-report"]);
  const virtualization = await loadJson(options["virtualization-report"]);
  const transform = await loadJson(options["transform-report"]);
  const protectionPolicy = await loadJson(options["protection-policy"]);
  const buildAttestation = await loadJson(options["build-attestation"]);
  const trustBundleBytes = await readFile(path.resolve(options["trust-bundle"]));
  const trustRootPublicKeyBytes = await readFile(path.resolve(options["trust-root-public-key"]));
  const timeEvaluationId = `provenance:${sha256(assessment.bytes)}`;
  const time = options["time-authority-client"]
    ? await authorizeLiveRemoteTime({ trustBundleBytes, trustRootPublicKeyBytes, product: null, evaluationId: timeEvaluationId, authorityClient: options["time-authority-client"], ledgerRoot: options["time-ledger"] })
    : await authorizeSignedRemoteTime({ trustBundleBytes, trustRootPublicKeyBytes, product: undefined, evaluationId: timeEvaluationId, timeAttestationBytes: await readFile(path.resolve(options["time-attestation"])), nonce: options["time-nonce"], ledgerRoot: options["time-ledger"] });
  if (time.clock.source !== "signed-live") throw new Error("production provenance requires live-challenged time");
  const trustBundle = time.trustBundle;
  const now = time.clock.milliseconds;
  if (artifact.value?.schemaVersion !== 1 || artifact.value?.status !== "passed" || !/^[a-f0-9]{64}$/.test(artifact.value?.artifactSha256 ?? "")) throw new Error("artifact report is not passed");
  const gate = verifyAssessmentGate(assessment.value, trustedRoleKey(trustBundle, "assessment-gate", assessment.value?.gateAttestation?.keyId).bytes);
  if (gate.core?.schemaVersion !== 8 || gate.core?.status !== "PASS" || gate.core?.artifactSha256 !== artifact.value.artifactSha256 || !/^[a-f0-9]{64}$/.test(gate.core?.assessmentSha256 ?? "") || !/^[a-f0-9]{64}$/.test(gate.core?.evidenceRootSha256 ?? "") || !/^[a-f0-9]{64}$/.test(gate.core?.deliveryGraph?.sha256 ?? "") || !/^[a-f0-9]{64}$/.test(gate.core?.protectionPolicy?.sha256 ?? "") || !/^[a-f0-9]{64}$/.test(gate.core?.protectionPolicy?.keyId ?? "")) throw new Error("assessment result is not a complete gate-signed PASS for this artifact");
  const gateClock = Date.parse(gate.core?.clock?.observedAt);
  if (gate.core?.clock?.source !== "signed-live" || !Number.isFinite(gateClock) || new Date(gateClock).toISOString() !== gate.core.clock.observedAt || gateClock > now + 5 * 60 * 1000 || gateClock < now - 24 * 60 * 60 * 1000) throw new Error("assessment gate was not produced with fresh live-challenged time");
  if (gate.core.trustBundle?.bundleId !== trustBundle.payload.bundleId || gate.core.trustBundle?.environment !== trustBundle.payload.environment || gate.core.trustBundle?.rootKeyId !== trustBundle.rootKeyId || gate.core.trustBundle?.sha256 !== trustBundle.envelopeSha256) throw new Error("assessment gate is not bound to the pinned trust bundle");
  const policy = verifyProtectionPolicyEnvelope(protectionPolicy.bytes, roleKeyForEnvelope(trustBundle, "protection-policy", protectionPolicy.bytes, "protection policy"));
  if (trustBundle.payload.product !== policy.payload.product) throw new Error("trust bundle product does not match the protection policy");
  if (protectionPolicy.sha256 !== gate.core.protectionPolicy.sha256 || policy.keyId !== gate.core.protectionPolicy.keyId || policy.payload.product !== gate.core.protectionPolicy.product) throw new Error("assessment gate is not bound to the supplied trusted protection policy");
  if (dependencies.packageLockSha256 !== policy.payload.protectorDependencies.packageLockSha256 || dependencies.closureSha256 !== policy.payload.protectorDependencies.closureSha256) throw new Error("installed protector dependency closure differs from owner policy");
  if (exposure.value?.schemaVersion !== 1 || exposure.value?.status !== "PASS" || exposure.value?.artifactVerification?.artifactSha256 !== artifact.value.artifactSha256) throw new Error("exposure report is not PASS for this artifact");
  const protectedTransform = verifyProtectionTransform(policy.payload.protectionTransform, virtualization.bytes, transform.bytes);
  if (sha256(await readFile(await realpath(virtualization.value.output.path))) !== virtualization.value.output.sha256) throw new Error("virtualization stage output no longer matches its receipt");
  if (protectedTransform.virtualizationSha256 !== virtualization.sha256 || protectedTransform.transformSha256 !== transform.sha256) throw new Error("protection receipt digest mismatch");
  const virtualizationInput = await realpath(path.resolve(options["virtualization-input"]));
  const virtualizationInputSha256 = await fileSha256(virtualizationInput);
  if (await realpath(virtualization.value.input.path) !== virtualizationInput || virtualization.value.input.sha256 !== virtualizationInputSha256) throw new Error("virtualization stage input does not match the product build output");
  const productRoot = await realpath(options["product-root"]); const productCommit = git(productRoot, ["rev-parse", "HEAD"]); const productTree = git(productRoot, ["rev-parse", "HEAD^{tree}"]);
  if (git(productRoot, ["status", "--porcelain=v1", "--untracked-files=all"])) throw new Error("product repository is dirty; release provenance requires a clean product tree");
  const buildDefinition = await realpath(path.resolve(options["build-definition"]));
  if (buildDefinition !== productRoot && !buildDefinition.startsWith(`${productRoot}${path.sep}`)) throw new Error("build definition is outside the product repository");
  const buildDefinitionPath = path.relative(productRoot, buildDefinition).split(path.sep).join("/");
  git(productRoot, ["ls-files", "--error-unmatch", "--", buildDefinitionPath]);
  const productPolicy = policy.payload.productSource;
  if (productCommit !== productPolicy.commit || productTree !== productPolicy.tree || await fileSha256(buildDefinition) !== productPolicy.buildDefinitionSha256) throw new Error("current product source does not match the owner-signed source policy");
  const configuredRemote = git(productRoot, ["config", "--get", "remote.origin.url"]);
  if (configuredRemote !== productPolicy.repositoryUri) throw new Error("product repository URI does not match the owner-signed source policy");
  const verifiedBuild = verifyProductBuildAttestation(buildAttestation.bytes, roleKeyForEnvelope(trustBundle, "product-builder", buildAttestation.bytes, "product build attestation"), { product: policy.payload.product, ...productPolicy, virtualizationInputSha256 });
  if (verifiedBuild.payload.buildDefinitionPath !== buildDefinitionPath) throw new Error("product build attestation buildDefinitionPath mismatch");
  const artifactRoot = await realpath(artifact.value.artifact);
  const transformOutput = await realpath(transform.value.output.path);
  if (transformOutput !== artifactRoot && !transformOutput.startsWith(`${artifactRoot}${path.sep}`)) throw new Error("transform output is outside the verified artifact");
  if (sha256(await readFile(transformOutput)) !== transform.value.output.sha256) throw new Error("transform stage output no longer matches its receipt");
  const nodePath = await realpath(process.execPath);
  const result = {
    schemaVersion: 1,
    format: "rea-hardening-provenance/v4",
    createdAt: time.clock.observedAt,
    clock: { source: time.clock.source, observedAt: time.clock.observedAt, keyId: time.clock.keyId, attestationSha256: time.clock.attestationSha256, nonce: time.clock.nonce, consumptionSha256: time.clock.consumptionSha256, requestSha256: time.clock.requestSha256, verifierRunId: time.clock.verifierRunId },
    source: { root, commit, dirty, diffSha256: sha256(diff) },
    trustBundle: { bundleId: trustBundle.payload.bundleId, environment: trustBundle.payload.environment, rootKeyId: trustBundle.rootKeyId, sha256: trustBundle.envelopeSha256 },
    productSource: {
      root: productRoot, repositoryUri: productPolicy.repositoryUri, commit: productCommit, tree: productTree, dirty: false,
      buildDefinition: { path: buildDefinitionPath, sha256: productPolicy.buildDefinitionSha256 },
      virtualizationInput: { path: virtualizationInput, sha256: virtualizationInputSha256 },
      protectionPolicy: { path: protectionPolicy.absolute, sha256: protectionPolicy.sha256, keyId: policy.keyId },
      buildAttestation: { path: buildAttestation.absolute, sha256: buildAttestation.sha256, keyId: verifiedBuild.keyId, runId: verifiedBuild.payload.runId, environmentSha256: verifiedBuild.payload.builderEnvironmentSha256 },
    },
    toolchain: {
      node: process.versions.node,
      v8: process.versions.v8,
      platform: process.platform,
      arch: process.arch,
      executable: { path: nodePath, sha256: await fileSha256(nodePath) },
      protectorVersion: JSON.parse(await readFile(path.join(root, "package.json"), "utf8")).version,
      protectorInventorySha256: protector.sha256,
      protectorFiles: protector.files,
      dependencies,
    },
    release: {
      artifactSha256: artifact.value.artifactSha256,
      artifactReportSha256: artifact.sha256,
      assessmentResultSha256: assessment.sha256,
      assessmentGateKeyId: gate.keyId,
      exposureReportSha256: exposure.sha256,
      virtualizationReportSha256: virtualization.sha256,
      transformReportSha256: transform.sha256,
    },
  };
  const handle = await open(path.resolve(options.out), "wx", 0o644);
  try { await handle.writeFile(`${JSON.stringify(result, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: "created", protectorCommit: commit, productCommit, productTree, artifactSha256: result.release.artifactSha256, protectorInventorySha256: protector.sha256, dependencyClosureSha256: dependencies.closureSha256, out: path.resolve(options.out) }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`provenance error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
