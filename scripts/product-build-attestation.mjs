#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { open, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const PRODUCT_BUILD_ATTESTATION_FORMAT = "rea-hardening-product-build-attestation/v1";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
}
function bounded(value, label, maximum = 128) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function digest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} must be lowercase SHA-256 hex`);
  return value;
}
function gitDigest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{40,64}$/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function instant(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`);
  return milliseconds;
}
function git(root, values, optional = false) {
  try { return execFileSync("git", ["-C", root, ...values], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim(); }
  catch (error) { if (optional) return ""; throw error; }
}

export function verifyProductBuildAttestation(envelopeBytes, publicKeyBytes, expected, nowValue = null) {
  const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8"));
  exactKeys(envelope, ["format", "keyId", "payload", "signature"], "product build attestation envelope");
  if (envelope.format !== PRODUCT_BUILD_ATTESTATION_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("product build attestation envelope is invalid");
  const publicKey = createPublicKey(publicKeyBytes);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("product builder public key must be Ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" }); const keyId = sha256(publicDer);
  if (keyId !== envelope.keyId || keyId !== expected.builderKeyId) throw new Error("product builder key is not trusted by owner policy");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${PRODUCT_BUILD_ATTESTATION_FORMAT}\0`), payloadBytes]), publicKey, Buffer.from(envelope.signature, "base64"))) throw new Error("product build attestation signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  if (!canonical(payload).equals(payloadBytes)) throw new Error("product build attestation payload is not canonical");
  exactKeys(payload, ["buildDefinitionPath", "buildDefinitionSha256", "builderEnvironmentSha256", "builderId", "commit", "expiresAt", "issuedAt", "product", "repositoryUri", "runId", "schemaVersion", "tree", "virtualizationInputSha256"], "product build attestation payload");
  if (payload.schemaVersion !== 1) throw new Error("product build attestation schema is unsupported");
  bounded(payload.product, "product"); bounded(payload.repositoryUri, "repositoryUri", 512); bounded(payload.builderId, "builderId"); bounded(payload.runId, "runId"); bounded(payload.buildDefinitionPath, "buildDefinitionPath", 512);
  gitDigest(payload.commit, "commit"); gitDigest(payload.tree, "tree"); digest(payload.buildDefinitionSha256, "buildDefinitionSha256"); digest(payload.builderEnvironmentSha256, "builderEnvironmentSha256"); digest(payload.virtualizationInputSha256, "virtualizationInputSha256");
  const issuedAt = instant(payload.issuedAt, "issuedAt"); const expiresAt = instant(payload.expiresAt, "expiresAt"); const now = nowValue === null ? Date.now() : instant(nowValue, "now");
  if (issuedAt > now + 5 * 60 * 1000 || expiresAt <= now || expiresAt > issuedAt + 24 * 60 * 60 * 1000) throw new Error("product build attestation is stale or has an invalid validity window");
  for (const [name, value] of Object.entries({
    product: expected.product, repositoryUri: expected.repositoryUri, commit: expected.commit, tree: expected.tree,
    buildDefinitionSha256: expected.buildDefinitionSha256, builderId: expected.builderId,
    builderEnvironmentSha256: expected.builderEnvironmentSha256,
  })) if (payload[name] !== value) throw new Error(`product build attestation ${name} mismatch`);
  if (expected.virtualizationInputSha256 && payload.virtualizationInputSha256 !== expected.virtualizationInputSha256) throw new Error("product build attestation virtualizationInputSha256 mismatch");
  return { keyId, payload, envelopeSha256: sha256(Buffer.from(envelopeBytes)) };
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: product-build-attestation.mjs sign --product NAME --product-root REPOSITORY --repository-uri URI --build-definition FILE --virtualization-input FILE --builder-id ID --environment-sha256 HEX --private-key PEM --run-id ID --expires-at ISO --out NEW.json\n");
  process.exit(64);
}
function args(argv) {
  const mode = argv.shift(); if (mode !== "sign") usage("mode must be sign");
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || options[key.slice(2)] !== undefined) usage("invalid arguments");
    options[key.slice(2)] = value;
  }
  for (const name of ["product", "product-root", "repository-uri", "build-definition", "virtualization-input", "builder-id", "environment-sha256", "private-key", "run-id", "expires-at", "out"]) if (!options[name]) usage(`--${name} is required`);
  return options;
}

async function main() {
  const options = args(process.argv.slice(2)); const root = await realpath(options["product-root"]);
  if (git(root, ["status", "--porcelain=v1", "--untracked-files=all"])) throw new Error("product repository is dirty; build attestation requires a clean tree");
  const commit = gitDigest(git(root, ["rev-parse", "HEAD"]), "commit"); const tree = gitDigest(git(root, ["rev-parse", "HEAD^{tree}"]), "tree");
  const repositoryUri = bounded(options["repository-uri"], "repository-uri", 512); const configuredRemote = git(root, ["config", "--get", "remote.origin.url"], true);
  if (configuredRemote && configuredRemote !== repositoryUri) throw new Error("repository-uri does not match remote.origin.url");
  const buildDefinition = await realpath(path.resolve(options["build-definition"]));
  if (buildDefinition !== root && !buildDefinition.startsWith(`${root}${path.sep}`)) throw new Error("build definition must be inside the product repository");
  const buildDefinitionPath = path.relative(root, buildDefinition).split(path.sep).join("/");
  git(root, ["ls-files", "--error-unmatch", "--", buildDefinitionPath]);
  const input = await realpath(path.resolve(options["virtualization-input"]));
  const issuedAt = new Date().toISOString(); const expiresAt = instant(options["expires-at"], "expires-at");
  if (expiresAt <= Date.now() || expiresAt > Date.now() + 24 * 60 * 60 * 1000) throw new Error("expires-at must be within the next 24 hours");
  const payload = {
    schemaVersion: 1, product: bounded(options.product, "product"), repositoryUri, commit, tree,
    buildDefinitionPath, buildDefinitionSha256: sha256(await readFile(buildDefinition)),
    virtualizationInputSha256: sha256(await readFile(input)), builderId: bounded(options["builder-id"], "builder-id"),
    builderEnvironmentSha256: digest(options["environment-sha256"], "environment-sha256"), runId: bounded(options["run-id"], "run-id"),
    issuedAt, expiresAt: new Date(expiresAt).toISOString(),
  };
  const payloadBytes = canonical(payload);
  const privateKey = createPrivateKey({ key: await readFile(path.resolve(options["private-key"])), passphrase: process.env.REA_PRODUCT_BUILDER_PASSPHRASE });
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("product builder private key must be Ed25519");
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const envelope = { format: PRODUCT_BUILD_ATTESTATION_FORMAT, keyId: sha256(publicDer), payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${PRODUCT_BUILD_ATTESTATION_FORMAT}\0`), payloadBytes]), privateKey).toString("base64") };
  const handle = await open(path.resolve(options.out), "wx", 0o644);
  try { await handle.writeFile(`${JSON.stringify(envelope, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: "signed", product: payload.product, commit, tree, virtualizationInputSha256: payload.virtualizationInputSha256, keyId: envelope.keyId, out: path.resolve(options.out) }, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => {
  process.stderr.write(`product build attestation error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
