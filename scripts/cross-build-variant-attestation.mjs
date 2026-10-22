#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const CROSS_BUILD_VARIANT_FORMAT = "rea-hardening-cross-build-variant/v1";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));
function exactKeys(value, keys, label) { if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`); }
function bounded(value, label, maximum = 128) { if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`); return value; }
function digest(value, label) { if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} must be lowercase SHA-256 hex`); return value; }
function instant(value, label) { const milliseconds = Date.parse(value); if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`); return milliseconds; }

export function validateCrossBuildVariantPayload(payload, nowValue = null) {
  exactKeys(payload, ["buildDefinitionSha256", "builderEnvironmentSha256", "builderId", "commit", "diversitySeedCommitment", "expiresAt", "issuedAt", "policySha256", "product", "regionSha256", "repositoryUri", "runId", "schemaVersion", "tree", "variantOrdinal"], "cross-build variant payload");
  if (payload.schemaVersion !== 1 || !Number.isSafeInteger(payload.variantOrdinal) || payload.variantOrdinal < 0 || payload.variantOrdinal >= 64) throw new Error("cross-build variant schema or ordinal is invalid");
  bounded(payload.product, "product"); bounded(payload.builderId, "builderId"); bounded(payload.runId, "runId"); bounded(payload.repositoryUri, "repositoryUri", 512);
  if (!/^[a-f0-9]{40,64}$/.test(payload.commit ?? "") || !/^[a-f0-9]{40,64}$/.test(payload.tree ?? "")) throw new Error("cross-build source identity is invalid");
  for (const field of ["buildDefinitionSha256", "builderEnvironmentSha256", "diversitySeedCommitment", "policySha256", "regionSha256"]) digest(payload[field], field);
  const issuedAt = instant(payload.issuedAt, "issuedAt"); const expiresAt = instant(payload.expiresAt, "expiresAt"); const now = nowValue === null ? Date.now() : instant(nowValue, "now");
  if (issuedAt > now + 5 * 60 * 1000 || expiresAt <= now || expiresAt > issuedAt + 24 * 60 * 60 * 1000) throw new Error("cross-build variant attestation is stale or has an invalid validity window");
  return payload;
}

export function verifyCrossBuildVariantEnvelope(envelopeBytes, publicKeyBytes, expected = {}, nowValue = null) {
  const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8")); exactKeys(envelope, ["format", "keyId", "payload", "signature"], "cross-build variant envelope");
  if (envelope.format !== CROSS_BUILD_VARIANT_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("cross-build variant envelope is invalid");
  const publicKey = createPublicKey(publicKeyBytes); if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("cross-build builder public key must be Ed25519");
  if (sha256(publicKey.export({ type: "spki", format: "der" })) !== envelope.keyId) throw new Error("cross-build builder key is not trusted");
  const payloadBytes = Buffer.from(envelope.payload, "base64"); if (!verify(null, Buffer.concat([Buffer.from(`${CROSS_BUILD_VARIANT_FORMAT}\0`), payloadBytes]), publicKey, Buffer.from(envelope.signature, "base64"))) throw new Error("cross-build variant signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8")); if (!canonical(payload).equals(payloadBytes)) throw new Error("cross-build variant payload is not canonical"); validateCrossBuildVariantPayload(payload, nowValue);
  for (const [field, value] of Object.entries(expected)) if (payload[field] !== value) throw new Error(`cross-build variant ${field} mismatch`);
  return { keyId: envelope.keyId, payload, envelopeSha256: sha256(Buffer.from(envelopeBytes)) };
}

function usage(message) { if (message) process.stderr.write(`${message}\n`); process.stderr.write("usage: cross-build-variant-attestation.mjs sign --descriptor FILE --private-key PEM --out NEW.json\n"); process.exit(64); }
function args(argv) { const mode = argv.shift(); if (mode !== "sign") usage("mode must be sign"); const result = {}; for (let index = 0; index < argv.length; index += 2) { const key = argv[index]; const value = argv[index + 1]; if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) usage("invalid arguments"); result[key.slice(2)] = value; } for (const name of ["descriptor", "private-key", "out"]) if (!result[name]) usage(`--${name} is required`); return result; }
async function main() {
  const options = args(process.argv.slice(2)); const payload = JSON.parse(await readFile(path.resolve(options.descriptor), "utf8")); validateCrossBuildVariantPayload(payload);
  const privateKey = createPrivateKey({ key: await readFile(path.resolve(options["private-key"])), passphrase: process.env.REA_PRODUCT_BUILDER_PASSPHRASE }); if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("cross-build builder private key must be Ed25519");
  const payloadBytes = canonical(payload); const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" }); const envelope = { format: CROSS_BUILD_VARIANT_FORMAT, keyId: sha256(publicDer), payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${CROSS_BUILD_VARIANT_FORMAT}\0`), payloadBytes]), privateKey).toString("base64") };
  const handle = await open(path.resolve(options.out), "wx", 0o644); try { await handle.writeFile(`${JSON.stringify(envelope, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: "signed", keyId: envelope.keyId, runId: payload.runId, regionSha256: payload.regionSha256, out: path.resolve(options.out) }, null, 2)}\n`);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`cross-build variant attestation error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
