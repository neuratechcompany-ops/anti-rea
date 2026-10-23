#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { open, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { verifyAssessmentGate } from "./assessment-gate.mjs";
import { verifyReleaseManifestEnvelope } from "./release-manifest.mjs";
import { verifyProtectionPolicyEnvelope } from "./protection-policy.mjs";
import { verifyProductBuildAttestation } from "./product-build-attestation.mjs";
import { verifyTripwireBundle } from "./llm-tripwire.mjs";
import { verifyProtectionTransform } from "./protection-transform.mjs";
import { trustedRoleKey } from "./trust-bundle.mjs";
import { authorizeLiveRemoteTime, authorizeSignedRemoteTime } from "./time-attestation.mjs";
import { inspectDependencyClosure } from "./dependency-closure.mjs";

export const RELEASE_ATTESTATION_FORMAT = "rea-hardening-release-attestation/v13";
const FORMAT = RELEASE_ATTESTATION_FORMAT;

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write([
    "usage:",
    "  release-attestation.mjs create --artifact-report FILE --assessment-result FILE --exposure-report FILE --virtualization-report FILE --transform-report FILE --provenance FILE --protection-policy FILE --build-attestation FILE --tripwire-root DIR --tripwire-manifest FILE --release-manifest FILE --trust-bundle SIGNED.json --trust-root-public-key PEM --time-authority-client EXECUTABLE --time-ledger DIR --private-key PEM --product NAME --channel NAME --release VERSION --sequence N --expires-at ISO --out NEW.json [--previous-attestation FILE]",
    "  release-attestation.mjs verify --attestation FILE --artifact-report FILE --assessment-result FILE --exposure-report FILE --virtualization-report FILE --transform-report FILE --provenance FILE --protection-policy FILE --build-attestation FILE --tripwire-root DIR --tripwire-manifest FILE --release-manifest FILE --trust-bundle SIGNED.json --trust-root-public-key PEM --time-authority-client EXECUTABLE --time-ledger DIR --product NAME --channel NAME --release VERSION --minimum-sequence N [--previous-attestation FILE]",
  ].join("\n") + "\n");
  process.exit(64);
}

function args(argv) {
  const mode = argv.shift();
  if (!new Set(["create", "verify"]).has(mode)) usage("mode must be create or verify");
  const result = { mode };
  const allowed = new Set(["artifact-report", "assessment-result", "exposure-report", "virtualization-report", "transform-report", "provenance", "protection-policy", "build-attestation", "tripwire-root", "tripwire-manifest", "release-manifest", "trust-bundle", "trust-root-public-key", "time-attestation", "time-nonce", "time-authority-client", "time-ledger", "product", "channel", "release", "private-key", "sequence", "expires-at", "out", "previous-attestation", "attestation", "minimum-sequence"]);
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    const name = key?.slice(2);
    if (!key?.startsWith("--") || value === undefined || !allowed.has(name) || result[name] !== undefined) usage("invalid arguments");
    result[name] = value;
  }
  const common = ["artifact-report", "assessment-result", "exposure-report", "virtualization-report", "transform-report", "provenance", "protection-policy", "build-attestation", "tripwire-root", "tripwire-manifest", "release-manifest", "trust-bundle", "trust-root-public-key", "time-ledger", "product", "channel", "release"];
  const required = mode === "create" ? [...common, "private-key", "sequence", "expires-at", "out"] : [...common, "attestation", "minimum-sequence"];
  for (const name of required) if (!result[name]) usage(`--${name} is required`);
  if ((result["time-attestation"] === undefined) !== (result["time-nonce"] === undefined) || (result["time-authority-client"] !== undefined) === (result["time-attestation"] !== undefined)) usage("provide exactly one live time authority client or file proof pair");
  if (result["time-nonce"] !== undefined && !/^[a-f0-9]{64}$/.test(result["time-nonce"])) usage("--time-nonce must be 32-byte lowercase hex");
  return result;
}

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function canonical(value) { return Buffer.from(JSON.stringify(value), "utf8"); }
function bounded(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function integer(value, label) {
  if (!/^[1-9][0-9]{0,14}$/.test(value ?? "") || !Number.isSafeInteger(Number(value))) throw new Error(`${label} is invalid`);
  return Number(value);
}
function instant(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`);
  return milliseconds;
}

async function load(file) {
  const absolute = path.resolve(file);
  const bytes = await readFile(absolute);
  return { absolute, bytes, sha256: sha256(bytes), value: JSON.parse(bytes.toString("utf8")) };
}

function envelopeKeyId(bytes, label) {
  const envelope = JSON.parse(Buffer.from(bytes).toString("utf8"));
  if (!/^[a-f0-9]{64}$/.test(envelope?.keyId ?? "")) throw new Error(`${label} lacks a valid keyId`);
  return envelope.keyId;
}
function roleKeyForEnvelope(trustBundle, role, bytes, label) {
  return trustedRoleKey(trustBundle, role, envelopeKeyId(bytes, label)).bytes;
}
async function authorizeOperationClock(options) {
  const trustBundleBytes = await readFile(path.resolve(options["trust-bundle"]));
  const assessmentBytes = await readFile(path.resolve(options["assessment-result"]));
  const common = {
    trustBundleBytes,
    trustRootPublicKeyBytes: await readFile(path.resolve(options["trust-root-public-key"])),
    product: options.product,
    evaluationId: `release:${sha256(assessmentBytes)}`,
    ledgerRoot: options["time-ledger"],
  };
  const authorized = options["time-authority-client"]
    ? authorizeLiveRemoteTime({ ...common, authorityClient: options["time-authority-client"] })
    : authorizeSignedRemoteTime({ ...common, timeAttestationBytes: await readFile(path.resolve(options["time-attestation"])), nonce: options["time-nonce"] });
  const resolved = await authorized; if (resolved.clock.source !== "signed-live") throw new Error("release operation requires live-challenged time"); return resolved;
}

async function evidence(options, now, trustBundle) {
  const artifact = await load(options["artifact-report"]);
  const assessment = await load(options["assessment-result"]);
  const exposure = await load(options["exposure-report"]);
  const virtualization = await load(options["virtualization-report"]);
  const transform = await load(options["transform-report"]);
  const provenance = await load(options.provenance);
  const manifest = await load(options["release-manifest"]);
  const protectionPolicy = await load(options["protection-policy"]);
  if (artifact.value?.schemaVersion !== 1 || artifact.value?.status !== "passed" || !/^[a-f0-9]{64}$/.test(artifact.value?.artifactSha256 ?? "")) throw new Error("artifact report is not passed");
  const gate = verifyAssessmentGate(assessment.value, roleKeyForEnvelope(trustBundle, "assessment-gate", Buffer.from(JSON.stringify(assessment.value.gateAttestation)), "assessment gate"));
  if (gate.core?.schemaVersion !== 8 || gate.core?.status !== "PASS" || gate.core?.artifactSha256 !== artifact.value.artifactSha256 || !/^[a-f0-9]{64}$/.test(gate.core?.assessmentSha256 ?? "") || !/^[a-f0-9]{64}$/.test(gate.core?.evidenceRootSha256 ?? "") || !/^[a-f0-9]{64}$/.test(gate.core?.deliveryGraph?.sha256 ?? "") || !/^[a-f0-9]{64}$/.test(gate.core?.protectionPolicy?.sha256 ?? "") || !/^[a-f0-9]{64}$/.test(gate.core?.protectionPolicy?.keyId ?? "")) throw new Error("assessment result is not a complete gate-signed PASS for this artifact");
  const gateClock = instant(gate.core?.clock?.observedAt, "assessment gate clock observedAt");
  if (gate.core?.clock?.source !== "signed-live" || gateClock > now + 5 * 60 * 1000 || gateClock < now - 24 * 60 * 60 * 1000) throw new Error("assessment gate was not produced with fresh live-challenged time");
  if (gate.core.protectionPolicy.product !== options.product) throw new Error("assessment protection policy product does not match the release product");
  if (gate.core.trustBundle?.bundleId !== trustBundle.payload.bundleId || gate.core.trustBundle?.environment !== trustBundle.payload.environment || gate.core.trustBundle?.rootKeyId !== trustBundle.rootKeyId || gate.core.trustBundle?.sha256 !== trustBundle.envelopeSha256) throw new Error("assessment gate is not bound to the pinned trust bundle");
  const policy = verifyProtectionPolicyEnvelope(protectionPolicy.bytes, roleKeyForEnvelope(trustBundle, "protection-policy", protectionPolicy.bytes, "protection policy"), new Date(now).toISOString());
  if (policy.payload.product !== options.product || protectionPolicy.sha256 !== gate.core.protectionPolicy.sha256 || policy.keyId !== gate.core.protectionPolicy.keyId) throw new Error("release evidence is not bound to the supplied trusted protection policy");
  const serverAuthorization = gate.core.serverAuthorization;
  if (!serverAuthorization || !/^[a-f0-9]{64}$/.test(serverAuthorization.keyId ?? "") || !/^[a-f0-9]{64}$/.test(serverAuthorization.transcriptSha256 ?? "") || !/^[a-f0-9]{64}$/.test(serverAuthorization.challengeSha256 ?? "")) throw new Error("assessment lacks complete server authorization evidence");
  trustedRoleKey(trustBundle, "server-authorization", serverAuthorization.keyId);
  if (serverAuthorization.product !== options.product || serverAuthorization.channel !== options.channel) throw new Error("server authorization scope does not match release product/channel");
  for (const name of ["environment", "channel", "action", "deploymentSha256", "configSha256", "transcriptSchemaSha256"]) if (serverAuthorization[name] !== policy.payload.serverAuthorization[name]) throw new Error(`server authorization ${name} differs from owner policy`);
  const serverIssuedAt = instant(serverAuthorization.issuedAt, "server authorization issuedAt");
  const serverExpiresAt = instant(serverAuthorization.expiresAt, "server authorization expiresAt");
  if (serverIssuedAt > now + 5 * 60 * 1000 || serverExpiresAt <= now || serverExpiresAt > serverIssuedAt + 24 * 60 * 60 * 1000) throw new Error("server authorization evidence is stale or has an invalid validity window");
  if (exposure.value?.schemaVersion !== 1 || exposure.value?.status !== "PASS" || exposure.value?.artifactVerification?.artifactSha256 !== artifact.value.artifactSha256) throw new Error("exposure report does not pass for this artifact");
  const protectedTransform = verifyProtectionTransform(policy.payload.protectionTransform, virtualization.bytes, transform.bytes);
  if (sha256(await readFile(await realpath(virtualization.value.output.path))) !== virtualization.value.output.sha256) throw new Error("virtualization stage output no longer matches its receipt");
  if (protectedTransform.virtualizationSha256 !== virtualization.sha256 || protectedTransform.transformSha256 !== transform.sha256) throw new Error("protection receipt digest mismatch");
  const artifactRoot = await realpath(artifact.value.artifact);
  const tripwire = await verifyTripwireBundle({ root: options["tripwire-root"], manifest: options["tripwire-manifest"], product: options.product, release: options.release });
  if (tripwire.root !== artifactRoot && !tripwire.root.startsWith(`${artifactRoot}${path.sep}`)) throw new Error("tripwire root is outside the verified artifact");
  const transformOutput = await realpath(transform.value.output.path);
  if (transformOutput !== artifactRoot && !transformOutput.startsWith(`${artifactRoot}${path.sep}`)) throw new Error("transform output is outside the verified artifact");
  if (sha256(await readFile(transformOutput)) !== transform.value.output.sha256) throw new Error("transform output no longer matches its receipt");
  if (provenance.value?.format !== "rea-hardening-provenance/v4" || provenance.value?.source?.dirty !== false || provenance.value?.productSource?.dirty !== false || provenance.value?.release?.artifactSha256 !== artifact.value.artifactSha256) throw new Error("provenance is invalid, dirty, or bound to another artifact");
  const provenanceClock = instant(provenance.value?.clock?.observedAt, "provenance clock observedAt");
  if (provenance.value?.clock?.source !== "signed-live" || [provenance.value?.clock?.keyId, provenance.value?.clock?.attestationSha256, provenance.value?.clock?.nonce, provenance.value?.clock?.consumptionSha256, provenance.value?.clock?.requestSha256, provenance.value?.clock?.verifierRunId].some((value) => !/^[a-f0-9]{64}$/.test(value ?? "")) || provenanceClock > now + 5 * 60 * 1000 || provenanceClock < now - 24 * 60 * 60 * 1000) throw new Error("provenance was not produced with fresh live-challenged time");
  if (provenance.value.trustBundle?.bundleId !== trustBundle.payload.bundleId || provenance.value.trustBundle?.environment !== trustBundle.payload.environment || provenance.value.trustBundle?.rootKeyId !== trustBundle.rootKeyId || provenance.value.trustBundle?.sha256 !== trustBundle.envelopeSha256) throw new Error("provenance is not bound to the pinned trust bundle");
  const dependencies = await inspectDependencyClosure(provenance.value.source.root);
  if (dependencies.packageLockSha256 !== policy.payload.protectorDependencies.packageLockSha256 || dependencies.closureSha256 !== policy.payload.protectorDependencies.closureSha256 || JSON.stringify(provenance.value.toolchain?.dependencies) !== JSON.stringify(dependencies)) throw new Error("protector dependency closure does not match owner policy and provenance");
  if (provenance.value.release.artifactReportSha256 !== artifact.sha256 || provenance.value.release.assessmentResultSha256 !== assessment.sha256 || provenance.value.release.assessmentGateKeyId !== gate.keyId || provenance.value.release.exposureReportSha256 !== exposure.sha256 || provenance.value.release.virtualizationReportSha256 !== virtualization.sha256 || provenance.value.release.transformReportSha256 !== transform.sha256) throw new Error("provenance evidence hashes do not match");
  const productSource = provenance.value.productSource;
  const sourcePolicy = policy.payload.productSource;
  if (productSource.repositoryUri !== sourcePolicy.repositoryUri || productSource.commit !== sourcePolicy.commit || productSource.tree !== sourcePolicy.tree || productSource.buildDefinition?.sha256 !== sourcePolicy.buildDefinitionSha256 || productSource.virtualizationInput?.sha256 !== virtualization.value.input.sha256 || productSource.protectionPolicy?.sha256 !== protectionPolicy.sha256 || productSource.protectionPolicy?.keyId !== policy.keyId) throw new Error("product-source provenance does not match trusted policy or virtualization input");
  const buildAttestation = await load(options["build-attestation"]);
  if (buildAttestation.sha256 !== productSource.buildAttestation?.sha256) throw new Error("product build attestation digest mismatch");
  const verifiedBuild = verifyProductBuildAttestation(buildAttestation.bytes, roleKeyForEnvelope(trustBundle, "product-builder", buildAttestation.bytes, "product build attestation"), { product: options.product, ...sourcePolicy, virtualizationInputSha256: productSource.virtualizationInput.sha256 }, new Date(now).toISOString());
  if (verifiedBuild.keyId !== productSource.buildAttestation.keyId || verifiedBuild.payload.runId !== productSource.buildAttestation.runId || verifiedBuild.payload.builderEnvironmentSha256 !== productSource.buildAttestation.environmentSha256) throw new Error("product build attestation provenance binding mismatch");
  const verifiedManifest = verifyReleaseManifestEnvelope(manifest.bytes, roleKeyForEnvelope(trustBundle, "release-manifest", manifest.bytes, "release manifest"), options.product, options.release);
  const manifestPayload = verifiedManifest.payload;
  if (manifestPayload.product !== options.product || manifestPayload.release !== options.release) throw new Error("release manifest product/release mismatch");
  if (!Array.isArray(manifestPayload.files) || manifestPayload.files.some((file) => typeof file?.path !== "string" || !Number.isSafeInteger(file?.bytes) || !/^[a-f0-9]{64}$/.test(file?.sha256 ?? ""))) throw new Error("release manifest inventory is invalid");
  const manifestArtifactSha256 = sha256(Buffer.from(manifestPayload.files.map((file) => `${file.path}\0${file.bytes}\0${file.sha256}`).join("\n")));
  if (manifestArtifactSha256 !== artifact.value.artifactSha256) throw new Error("release manifest inventory does not match the verified artifact");
  return {
    artifactSha256: artifact.value.artifactSha256,
    bindings: {
      artifactReportSha256: artifact.sha256,
      assessmentResultSha256: assessment.sha256,
      assessmentGateKeyId: gate.keyId,
      exposureReportSha256: exposure.sha256,
      virtualizationReportSha256: virtualization.sha256,
      transformReportSha256: transform.sha256,
      provenanceSha256: provenance.sha256,
      releaseManifestSha256: manifest.sha256,
      releaseManifestKeyId: verifiedManifest.keyId,
      protectionPolicySha256: protectionPolicy.sha256,
      productBuildAttestationSha256: buildAttestation.sha256,
      tripwireManifestSha256: tripwire.manifestSha256,
      trustBundleSha256: trustBundle.envelopeSha256,
    },
  };
}

function parseEnvelope(bytes, publicKey) {
  const envelope = JSON.parse(bytes.toString("utf8"));
  if (!envelope || envelope.format !== FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("attestation envelope is invalid");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  const signature = Buffer.from(envelope.signature, "base64");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (envelope.keyId !== sha256(publicDer)) throw new Error("attestation key id mismatch");
  if (!verify(null, Buffer.concat([Buffer.from(`${FORMAT}\0`), payloadBytes]), publicKey, signature)) throw new Error("attestation signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  if (!canonical(payload).equals(payloadBytes)) throw new Error("attestation payload is not canonical");
  return { envelope, payload };
}

function validatePayload(payload) {
  const keys = ["artifactSha256", "bindings", "channel", "clock", "expiresAt", "issuedAt", "previous", "product", "release", "schemaVersion", "sequence"];
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || Object.keys(payload).sort().join("|") !== keys.sort().join("|")) throw new Error("attestation payload fields are invalid");
  if (payload.schemaVersion !== 1 || !/^[a-f0-9]{64}$/.test(payload.artifactSha256 ?? "") || !Number.isSafeInteger(payload.sequence) || payload.sequence < 1) throw new Error("attestation payload identity is invalid");
  bounded(payload.product, "payload product"); bounded(payload.channel, "payload channel"); bounded(payload.release, "payload release");
  const issuedAt = instant(payload.issuedAt, "payload issuedAt"); const expiresAt = instant(payload.expiresAt, "payload expiresAt");
  if (expiresAt <= issuedAt || expiresAt > issuedAt + 366 * 24 * 60 * 60 * 1000) throw new Error("attestation validity window is invalid");
  const clockKeys = ["attestationSha256", "consumptionSha256", "keyId", "nonce", "observedAt", "requestSha256", "source", "verifierRunId"];
  if (!payload.clock || Object.keys(payload.clock).sort().join("|") !== clockKeys.sort().join("|") || payload.clock.source !== "signed-live" || payload.clock.observedAt !== payload.issuedAt || [payload.clock.keyId, payload.clock.attestationSha256, payload.clock.consumptionSha256, payload.clock.nonce, payload.clock.requestSha256, payload.clock.verifierRunId].some((value) => !/^[a-f0-9]{64}$/.test(value))) throw new Error("attestation clock binding is invalid");
  const bindingKeys = ["artifactReportSha256", "assessmentResultSha256", "assessmentGateKeyId", "exposureReportSha256", "virtualizationReportSha256", "transformReportSha256", "provenanceSha256", "releaseManifestSha256", "releaseManifestKeyId", "protectionPolicySha256", "productBuildAttestationSha256", "tripwireManifestSha256", "trustBundleSha256"];
  if (!payload.bindings || Object.keys(payload.bindings).sort().join("|") !== bindingKeys.sort().join("|") || Object.values(payload.bindings).some((value) => !/^[a-f0-9]{64}$/.test(value))) throw new Error("attestation bindings are invalid");
  if ((payload.sequence === 1) !== (payload.previous === null)) throw new Error("previous attestation binding is invalid");
  if (payload.previous !== null && (!payload.previous || Array.isArray(payload.previous) || Object.keys(payload.previous).sort().join("|") !== "attestationSha256|sequence" || !Number.isSafeInteger(payload.previous.sequence) || payload.previous.sequence !== payload.sequence - 1 || !/^[a-f0-9]{64}$/.test(payload.previous.attestationSha256 ?? ""))) throw new Error("previous attestation binding is invalid");
}

export function verifyReleaseAttestationEnvelope(bytes, trustBundle, { product, channel, release, minimumSequence = 1, clock } = {}) {
  if (!Number.isFinite(clock?.milliseconds) || new Date(clock.milliseconds).toISOString() !== clock.observedAt || clock.source !== "signed-live") throw new Error("release attestation verifier requires live-challenged time");
  const current = clock.milliseconds;
  const publicKey = createPublicKey(roleKeyForEnvelope(trustBundle, "release-attestation", bytes, "release attestation"));
  const parsed = parseEnvelope(Buffer.from(bytes), publicKey); validatePayload(parsed.payload);
  if (parsed.payload.product !== product || parsed.payload.channel !== channel || parsed.payload.release !== release) throw new Error("trusted product/channel/release mismatch");
  if (!Number.isSafeInteger(minimumSequence) || minimumSequence < 1 || parsed.payload.sequence < minimumSequence) throw new Error(`rollback rejected: sequence ${parsed.payload.sequence} is below trusted minimum ${minimumSequence}`);
  if (instant(parsed.payload.expiresAt, "payload expiresAt") <= current) throw new Error("attestation is expired");
  if (instant(parsed.payload.issuedAt, "payload issuedAt") > current + 5 * 60 * 1000) throw new Error("attestation issuance time is in the future");
  if ((parsed.payload.sequence === 1) !== (parsed.payload.previous === null)) throw new Error("release attestation predecessor shape is invalid");
  return { keyId: parsed.envelope.keyId, payload: parsed.payload, sha256: sha256(Buffer.from(bytes)), clock };
}

async function create(options) {
  const sequence = integer(options.sequence, "sequence");
  const expiresAt = instant(options["expires-at"], "expires-at");
  const time = await authorizeOperationClock(options); const now = time.clock.milliseconds;
  if (expiresAt <= now || expiresAt > now + 366 * 24 * 60 * 60 * 1000) throw new Error("expires-at must be in the future and no more than 366 days away");
  const privateKey = createPrivateKey({ key: await readFile(options["private-key"]), passphrase: process.env.REA_ATTESTATION_PASSPHRASE });
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("private key must be Ed25519");
  const publicKey = createPublicKey(privateKey);
  const trustBundle = time.trustBundle;
  const currentReleaseKeyId = sha256(publicKey.export({ type: "spki", format: "der" }));
  trustedRoleKey(trustBundle, "release-attestation", currentReleaseKeyId);
  let previous = null;
  if (options["previous-attestation"]) {
    const previousBytes = await readFile(options["previous-attestation"]);
    const previousKey = createPublicKey(roleKeyForEnvelope(trustBundle, "release-attestation", previousBytes, "previous release attestation"));
    const parsed = parseEnvelope(previousBytes, previousKey); validatePayload(parsed.payload);
    if (parsed.payload.product !== options.product || parsed.payload.channel !== options.channel || parsed.payload.sequence !== sequence - 1) throw new Error("previous attestation must be the immediate predecessor in this product/channel");
    previous = { sequence: parsed.payload.sequence, attestationSha256: sha256(previousBytes) };
  }
  if (sequence > 1 && previous === null) throw new Error("sequence above genesis requires the immediate previous attestation");
  if (sequence === 1 && previous !== null) throw new Error("genesis sequence cannot have a previous attestation");
  const bound = await evidence(options, now, trustBundle);
  const payload = {
    schemaVersion: 1,
    product: bounded(options.product, "product"),
    channel: bounded(options.channel, "channel"),
    release: bounded(options.release, "release"),
    sequence,
    issuedAt: time.clock.observedAt,
    expiresAt: new Date(expiresAt).toISOString(),
    clock: { source: time.clock.source, observedAt: time.clock.observedAt, keyId: time.clock.keyId, attestationSha256: time.clock.attestationSha256, nonce: time.clock.nonce, consumptionSha256: time.clock.consumptionSha256, requestSha256: time.clock.requestSha256, verifierRunId: time.clock.verifierRunId },
    artifactSha256: bound.artifactSha256,
    bindings: bound.bindings,
    previous,
  };
  const payloadBytes = canonical(payload);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const envelope = {
    format: FORMAT,
    keyId: sha256(publicDer),
    payload: payloadBytes.toString("base64"),
    signature: sign(null, Buffer.concat([Buffer.from(`${FORMAT}\0`), payloadBytes]), privateKey).toString("base64"),
  };
  const handle = await open(path.resolve(options.out), "wx", 0o644);
  try { await handle.writeFile(`${JSON.stringify(envelope, null, 2)}\n`); } finally { await handle.close(); }
  return { status: "created", sequence, expiresAt: payload.expiresAt, artifactSha256: payload.artifactSha256, keyId: envelope.keyId, out: path.resolve(options.out) };
}

async function verifyAttestation(options) {
  const time = await authorizeOperationClock(options); const now = time.clock.milliseconds;
  const trustBundle = time.trustBundle;
  const attestation = await load(options.attestation);
  const publicKey = createPublicKey(roleKeyForEnvelope(trustBundle, "release-attestation", attestation.bytes, "release attestation"));
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("release attestation public key must be Ed25519");
  const parsed = parseEnvelope(attestation.bytes, publicKey); validatePayload(parsed.payload);
  const minimum = integer(options["minimum-sequence"], "minimum-sequence");
  if (parsed.payload.product !== options.product || parsed.payload.channel !== options.channel || parsed.payload.release !== options.release) throw new Error("trusted product/channel/release mismatch");
  if (parsed.payload.sequence < minimum) throw new Error(`rollback rejected: sequence ${parsed.payload.sequence} is below trusted minimum ${minimum}`);
  if (instant(parsed.payload.expiresAt, "payload expiresAt") <= now) throw new Error("attestation is expired");
  if (instant(parsed.payload.issuedAt, "payload issuedAt") > now + 5 * 60 * 1000) throw new Error("attestation issuance time is in the future");
  if (parsed.payload.sequence > 1 && parsed.payload.previous === null) throw new Error("non-genesis attestation lacks its immediate predecessor binding");
  if (parsed.payload.sequence === 1 && parsed.payload.previous !== null) throw new Error("genesis attestation has an invalid predecessor binding");
  const bound = await evidence(options, now, trustBundle);
  if (parsed.payload.artifactSha256 !== bound.artifactSha256 || JSON.stringify(parsed.payload.bindings) !== JSON.stringify(bound.bindings)) throw new Error("attestation evidence bindings do not match");
  if (parsed.payload.previous !== null) {
    if (!options["previous-attestation"]) throw new Error("previous attestation is required to verify this chain link");
    const previousBytes = await readFile(options["previous-attestation"]);
    const previousKey = createPublicKey(roleKeyForEnvelope(trustBundle, "release-attestation", previousBytes, "previous release attestation"));
    const previous = parseEnvelope(previousBytes, previousKey); validatePayload(previous.payload);
    if (sha256(previousBytes) !== parsed.payload.previous.attestationSha256 || previous.payload.sequence !== parsed.payload.previous.sequence || previous.payload.product !== parsed.payload.product || previous.payload.channel !== parsed.payload.channel || previous.payload.sequence !== parsed.payload.sequence - 1) throw new Error("previous attestation chain binding is invalid");
  }
  return { status: "verified", sequence: parsed.payload.sequence, minimumSequence: minimum, expiresAt: parsed.payload.expiresAt, artifactSha256: parsed.payload.artifactSha256, keyId: parsed.envelope.keyId };
}

async function main() {
  const options = args(process.argv.slice(2));
  const result = options.mode === "create" ? await create(options) : await verifyAttestation(options);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => {
  process.stderr.write(`release attestation error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
