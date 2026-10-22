#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { resolveTrustedTime } from "./trusted-time.mjs";

export const PROTECTION_POLICY_FORMAT = "rea-hardening-protection-policy/v6";
const TIERS = new Set(["T0", "T1", "T2", "T3"]);
const PROBES = new Set(["anti-rea-vm-runtime-hook", "anti-rea-vm-public-deobfuscator", "anti-rea-behavior-holdout", "anti-rea-cross-build-alignment", "anti-rea-cross-build-semantic"]);
const REGRESSION_KINDS = new Set(["functional", "performance", "platform-security"]);
const DELIVERY_KINDS = new Set(["release", "update", "crash", "support", "symbols"]);

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
}
function bounded(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function repositoryUri(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function digest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} must be lowercase SHA-256 hex`);
  return value;
}
function instant(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`);
  return milliseconds;
}
function uniqueStrings(value, label, pattern = null) {
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || !item || (pattern && !pattern.test(item))) || new Set(value).size !== value.length) throw new Error(`${label} must be a nonempty unique string array`);
  return value;
}

export function validateProtectionPolicy(payload, nowValue = null) {
  exactKeys(payload, ["analyzers", "comparisons", "deliverySurfaces", "evidenceWorkerKeyIds", "expiresAt", "exposurePolicySha256", "issuedAt", "policyId", "product", "productSource", "protectionTransform", "protectorDependencies", "regressionTests", "schemaVersion", "serverAuthorization"], "policy");
  if (payload.schemaVersion !== 6) throw new Error("unsupported protection policy schema; version 6 is required");
  bounded(payload.policyId, "policyId"); bounded(payload.product, "product");
  digest(payload.exposurePolicySha256, "exposurePolicySha256");
  exactKeys(payload.productSource, ["buildDefinitionSha256", "builderEnvironmentSha256", "builderId", "builderKeyId", "commit", "repositoryUri", "tree"], "productSource");
  repositoryUri(payload.productSource.repositoryUri, "productSource.repositoryUri"); bounded(payload.productSource.builderId, "productSource.builderId");
  if (!/^[a-f0-9]{40,64}$/.test(payload.productSource.commit ?? "") || !/^[a-f0-9]{40,64}$/.test(payload.productSource.tree ?? "")) throw new Error("productSource commit or tree is invalid");
  for (const name of ["buildDefinitionSha256", "builderEnvironmentSha256", "builderKeyId"]) digest(payload.productSource[name], `productSource.${name}`);
  exactKeys(payload.protectorDependencies, ["closureSha256", "packageLockSha256"], "protectorDependencies");
  digest(payload.protectorDependencies.packageLockSha256, "protectorDependencies.packageLockSha256"); digest(payload.protectorDependencies.closureSha256, "protectorDependencies.closureSha256");
  exactKeys(payload.protectionTransform, ["backend", "claimTier", "encryption", "keyMode", "profileId", "profileSha256", "surface", "transformerName", "transformerVersion", "virtualizerName", "virtualizerVersion"], "protectionTransform");
  const transform = payload.protectionTransform;
  for (const name of ["backend", "encryption", "profileId", "surface", "transformerName", "transformerVersion", "virtualizerName", "virtualizerVersion"]) bounded(transform[name], `protectionTransform.${name}`);
  digest(transform.profileSha256, "protectionTransform.profileSha256");
  if (transform.backend !== "selective-vm+javascript-obfuscator" || transform.surface !== "javascript" || transform.virtualizerName !== "anti-rea-selective-vm" || transform.transformerName !== "javascript-obfuscator") throw new Error("protectionTransform selects an unsupported protection pipeline");
  if (!new Set(["embedded", "external"]).has(transform.keyMode)) throw new Error("protectionTransform.keyMode is invalid");
  if (!TIERS.has(transform.claimTier)) throw new Error("protectionTransform.claimTier must be T0, T1, T2, or T3");
  if (transform.keyMode === "external" && transform.encryption !== "chacha20-poly1305") throw new Error("external key mode requires chacha20-poly1305");
  if (transform.keyMode === "embedded" && transform.encryption !== "embedded-xorshift") throw new Error("embedded key mode requires embedded-xorshift");
  if (transform.claimTier !== "T0" && transform.keyMode !== "external") throw new Error("T1+ claim requires external key mode");
  exactKeys(payload.serverAuthorization, ["action", "channel", "configSha256", "deploymentSha256", "environment", "transcriptSchemaSha256"], "serverAuthorization");
  for (const name of ["action", "channel", "environment"]) bounded(payload.serverAuthorization[name], `serverAuthorization.${name}`);
  for (const name of ["configSha256", "deploymentSha256", "transcriptSchemaSha256"]) digest(payload.serverAuthorization[name], `serverAuthorization.${name}`);
  const workerKeys = uniqueStrings(payload.evidenceWorkerKeyIds, "evidenceWorkerKeyIds");
  for (const [index, keyId] of workerKeys.entries()) digest(keyId, `evidenceWorkerKeyIds[${index}]`);
  const issuedAt = instant(payload.issuedAt, "issuedAt");
  const expiresAt = instant(payload.expiresAt, "expiresAt");
  const now = nowValue === null ? Date.now() : instant(nowValue, "now");
  if (issuedAt > now + 5 * 60 * 1000 || expiresAt <= now || expiresAt > issuedAt + 31 * 24 * 60 * 60 * 1000) throw new Error("protection policy is stale or has an invalid validity window");

  if (!Array.isArray(payload.deliverySurfaces) || payload.deliverySurfaces.length !== DELIVERY_KINDS.size) throw new Error("policy requires exactly one declaration for every delivery surface kind");
  const deliveryKinds = new Set(); const deliveryIds = new Set();
  for (const [index, surface] of payload.deliverySurfaces.entries()) {
    exactKeys(surface, ["audience", "disposition", "id", "kind", "rationale"], `deliverySurfaces[${index}]`);
    if (!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(surface.id ?? "") || deliveryIds.has(surface.id)) throw new Error(`deliverySurfaces[${index}].id is invalid or duplicate`);
    deliveryIds.add(surface.id);
    if (!DELIVERY_KINDS.has(surface.kind) || deliveryKinds.has(surface.kind)) throw new Error(`deliverySurfaces[${index}].kind is invalid or duplicate`);
    deliveryKinds.add(surface.kind);
    if (!new Set(["present", "not-applicable"]).has(surface.disposition)) throw new Error(`deliverySurfaces[${index}].disposition is invalid`);
    if (!new Set(["customer", "internal", "none"]).has(surface.audience)) throw new Error(`deliverySurfaces[${index}].audience is invalid`);
    bounded(surface.rationale, `deliverySurfaces[${index}].rationale`);
    if ((surface.disposition === "not-applicable") !== (surface.audience === "none")) throw new Error(`deliverySurfaces[${index}] not-applicable declarations require audience none`);
    if (surface.kind === "release" && (surface.disposition !== "present" || surface.audience !== "customer")) throw new Error("release delivery surface must be present and customer-visible");
    if (surface.kind === "update" && (surface.disposition !== "present" || surface.audience !== "customer")) throw new Error("update delivery surface must be present and customer-visible");
    if (surface.kind === "symbols" && surface.disposition === "present" && surface.audience !== "internal") throw new Error("symbol delivery surface must be internal");
  }

  if (!Array.isArray(payload.analyzers) || payload.analyzers.length < 2) throw new Error("policy requires at least two analyzer identities");
  const analyzerFamilies = new Set();
  for (const [index, analyzer] of payload.analyzers.entries()) {
    exactKeys(analyzer, ["adapterSha256", "executableSha256", "family"], `analyzers[${index}]`);
    if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(analyzer.family ?? "") || analyzerFamilies.has(analyzer.family)) throw new Error(`analyzers[${index}].family is invalid or duplicate`);
    analyzerFamilies.add(analyzer.family);
    digest(analyzer.adapterSha256, `analyzers[${index}].adapterSha256`);
    digest(analyzer.executableSha256, `analyzers[${index}].executableSha256`);
  }

  if (!Array.isArray(payload.regressionTests) || payload.regressionTests.length !== REGRESSION_KINDS.size) throw new Error("policy requires exactly one identity for each regression test kind");
  const regressionKinds = new Set();
  for (const [index, regression] of payload.regressionTests.entries()) {
    exactKeys(regression, ["environmentSha256", "kind", "runnerExecutableSha256", "runnerId", "suiteId", "suiteSha256"], `regressionTests[${index}]`);
    if (!REGRESSION_KINDS.has(regression.kind) || regressionKinds.has(regression.kind)) throw new Error(`regressionTests[${index}].kind is invalid or duplicate`);
    regressionKinds.add(regression.kind);
    bounded(regression.suiteId, `regressionTests[${index}].suiteId`); bounded(regression.runnerId, `regressionTests[${index}].runnerId`);
    digest(regression.suiteSha256, `regressionTests[${index}].suiteSha256`);
    digest(regression.runnerExecutableSha256, `regressionTests[${index}].runnerExecutableSha256`);
    digest(regression.environmentSha256, `regressionTests[${index}].environmentSha256`);
  }

  if (!Array.isArray(payload.comparisons) || payload.comparisons.length === 0) throw new Error("policy requires comparisons");
  const comparisonIds = new Set();
  for (const [index, comparison] of payload.comparisons.entries()) {
    exactKeys(comparison, ["factIds", "id", "minimumImprovement", "requiredAnalyzerFamilies", "requiredProbes", "targetMax", "tier"], `comparisons[${index}]`);
    if (!/^[A-Z][A-Z0-9-]{1,63}$/.test(comparison.id ?? "") || comparisonIds.has(comparison.id)) throw new Error(`comparisons[${index}].id is invalid or duplicate`);
    comparisonIds.add(comparison.id);
    if (!TIERS.has(comparison.tier)) throw new Error(`comparisons[${index}].tier is invalid`);
    if (!Number.isInteger(comparison.targetMax) || comparison.targetMax < 0 || comparison.targetMax > 4) throw new Error(`comparisons[${index}].targetMax is invalid`);
    if (!Number.isInteger(comparison.minimumImprovement) || comparison.minimumImprovement < 1 || comparison.minimumImprovement > 4) throw new Error(`comparisons[${index}].minimumImprovement is invalid`);
    uniqueStrings(comparison.factIds, `comparisons[${index}].factIds`, /^[A-Z][A-Z0-9-]{1,63}$/);
    const families = uniqueStrings(comparison.requiredAnalyzerFamilies, `comparisons[${index}].requiredAnalyzerFamilies`, /^[a-z0-9][a-z0-9-]{1,62}$/);
    for (const family of families) if (!analyzerFamilies.has(family)) throw new Error(`comparisons[${index}] references unknown analyzer family ${family}`);
    const probes = uniqueStrings(comparison.requiredProbes, `comparisons[${index}].requiredProbes`);
    for (const probe of probes) if (!PROBES.has(probe)) throw new Error(`comparisons[${index}] references unsupported probe ${probe}`);
  }
  return payload;
}

export function verifyProtectionPolicyEnvelope(envelopeBytes, publicKeyBytes, nowValue = null) {
  const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8"));
  exactKeys(envelope, ["format", "keyId", "payload", "signature"], "policy envelope");
  if (envelope.format !== PROTECTION_POLICY_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("protection policy envelope is invalid");
  const publicKey = createPublicKey(publicKeyBytes);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("protection policy public key must be Ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (sha256(publicDer) !== envelope.keyId) throw new Error("protection policy key is not trusted");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${PROTECTION_POLICY_FORMAT}\0`), payloadBytes]), publicKey, Buffer.from(envelope.signature, "base64"))) throw new Error("protection policy signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  if (!Buffer.from(JSON.stringify(payload)).equals(payloadBytes)) throw new Error("protection policy payload is not canonical");
  validateProtectionPolicy(payload, nowValue);
  return { keyId: envelope.keyId, payload, envelopeSha256: sha256(Buffer.from(envelopeBytes)) };
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write([
    "usage:",
    "  protection-policy.mjs sign --policy POLICY.json --private-key PEM --out NEW.json",
    "  protection-policy.mjs verify --policy SIGNED.json --public-key PEM [--now ISO]",
  ].join("\n") + "\n");
  process.exit(64);
}

function args(argv) {
  const mode = argv.shift();
  if (!new Set(["sign", "verify"]).has(mode)) usage("mode must be sign or verify");
  const result = { mode };
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) usage("invalid arguments");
    result[key.slice(2)] = value;
  }
  const required = mode === "sign" ? ["policy", "private-key", "out"] : ["policy", "public-key"];
  for (const name of required) if (!result[name]) usage(`--${name} is required`);
  return result;
}

async function writeExclusive(destination, bytes) {
  const handle = await open(destination, "wx", 0o644);
  try { await handle.writeFile(bytes); } finally { await handle.close(); }
}

async function main() {
  const options = args(process.argv.slice(2));
  if (options.mode === "sign") {
    const payload = JSON.parse(await readFile(path.resolve(options.policy), "utf8"));
    validateProtectionPolicy(payload);
    const privateKey = createPrivateKey({ key: await readFile(path.resolve(options["private-key"])), passphrase: process.env.REA_POLICY_PASSPHRASE });
    if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("protection policy private key must be Ed25519");
    const payloadBytes = Buffer.from(JSON.stringify(payload));
    const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
    const envelope = {
      format: PROTECTION_POLICY_FORMAT,
      keyId: sha256(publicDer),
      payload: payloadBytes.toString("base64"),
      signature: sign(null, Buffer.concat([Buffer.from(`${PROTECTION_POLICY_FORMAT}\0`), payloadBytes]), privateKey).toString("base64"),
    };
    await writeExclusive(path.resolve(options.out), `${JSON.stringify(envelope, null, 2)}\n`);
    process.stdout.write(`${JSON.stringify({ status: "signed", policyId: payload.policyId, product: payload.product, keyId: envelope.keyId, out: path.resolve(options.out) }, null, 2)}\n`);
  } else {
    const verified = verifyProtectionPolicyEnvelope(await readFile(path.resolve(options.policy)), await readFile(path.resolve(options["public-key"])), resolveTrustedTime(options.now ?? null).observedAt);
    process.stdout.write(`${JSON.stringify({ status: "verified", policyId: verified.payload.policyId, product: verified.payload.product, keyId: verified.keyId, sha256: verified.envelopeSha256, protectionTransform: verified.payload.protectionTransform }, null, 2)}\n`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => {
  process.stderr.write(`protection policy error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
