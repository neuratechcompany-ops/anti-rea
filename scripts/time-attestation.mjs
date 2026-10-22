#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { trustedRoleKey, verifyTrustBundleEnvelope, verifyTrustBundleEnvelopeSignature } from "./trust-bundle.mjs";

export const TIME_ATTESTATION_FORMAT = "rea-hardening-time-attestation/v1";
export const TIME_CONSUMPTION_FORMAT = "rea-hardening-time-consumption/v1";
export const TIME_REQUEST_FORMAT = "rea-hardening-time-request/v1";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));
function exactKeys(value, keys, label) { if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`); }
function bounded(value, label, maximum = 128) { if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`); return value; }
function instant(value, label) { const milliseconds = Date.parse(value); if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`); return milliseconds; }
function validatePayload(payload) {
  exactKeys(payload, ["authorityRunId", "environment", "evaluationId", "nonce", "observedAt", "product", "schemaVersion"], "time attestation payload");
  if (payload.schemaVersion !== 1 || !/^[a-f0-9]{64}$/.test(payload.nonce ?? "") || !/^[a-f0-9]{64}$/.test(payload.authorityRunId ?? "")) throw new Error("time attestation identity is invalid");
  bounded(payload.product, "product"); bounded(payload.environment, "environment"); bounded(payload.evaluationId, "evaluationId"); instant(payload.observedAt, "observedAt"); return payload;
}
function publicIdentity(key) { const publicKey = key?.type === "public" ? key : createPublicKey(key); if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("time authority key must be Ed25519"); const der = publicKey.export({ type: "spki", format: "der" }); return { key: publicKey, keyId: sha256(der) }; }

export function createTimeAttestationEnvelope(payloadValue, privateKeyValue) {
  const payload = validatePayload(structuredClone(payloadValue)); const privateKey = privateKeyValue?.type === "private" ? privateKeyValue : createPrivateKey(privateKeyValue); if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("time authority private key must be Ed25519");
  const keyId = publicIdentity(createPublicKey(privateKey)).keyId; const payloadBytes = canonical(payload);
  return { format: TIME_ATTESTATION_FORMAT, keyId, payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${TIME_ATTESTATION_FORMAT}\0`), payloadBytes]), privateKey).toString("base64") };
}

export function verifyTimeAttestationEnvelope(envelopeBytes, publicKeyValue, expected = {}) {
  const bytes = Buffer.from(envelopeBytes); const envelope = JSON.parse(bytes.toString("utf8")); exactKeys(envelope, ["format", "keyId", "payload", "signature"], "time attestation envelope");
  if (envelope.format !== TIME_ATTESTATION_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("time attestation envelope is invalid");
  const identity = publicIdentity(publicKeyValue); if (identity.keyId !== envelope.keyId) throw new Error("time authority key is not trusted"); const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${TIME_ATTESTATION_FORMAT}\0`), payloadBytes]), identity.key, Buffer.from(envelope.signature, "base64"))) throw new Error("time attestation signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8")); if (!canonical(payload).equals(payloadBytes)) throw new Error("time attestation payload is not canonical"); validatePayload(payload);
  for (const [name, value] of Object.entries(expected)) if (value !== undefined && payload[name] !== value) throw new Error(`time attestation ${name} mismatch`);
  return { keyId: envelope.keyId, envelopeSha256: sha256(bytes), payload, clock: { source: "signed-remote", milliseconds: Date.parse(payload.observedAt), observedAt: payload.observedAt, keyId: envelope.keyId, attestationSha256: sha256(bytes), nonce: payload.nonce } };
}

export async function consumeTimeAttestation(ledgerRootValue, verified, evaluationId) {
  bounded(evaluationId, "evaluationId"); if (verified.payload.evaluationId !== evaluationId) throw new Error("time attestation evaluationId mismatch");
  const ledgerRoot = await realpath(path.resolve(ledgerRootValue)); if (!(await lstat(ledgerRoot)).isDirectory()) throw new Error("time attestation ledger must be a directory");
  const record = { format: TIME_CONSUMPTION_FORMAT, schemaVersion: 1, nonce: verified.payload.nonce, attestationSha256: verified.envelopeSha256, authorityRunId: verified.payload.authorityRunId, evaluationId, observedAt: verified.payload.observedAt };
  const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`); const destination = path.join(ledgerRoot, `time-${record.nonce}.json`); let handle;
  try { handle = await open(destination, "wx", 0o444); } catch (error) { if (error?.code === "EEXIST") throw new Error(`time attestation nonce ${record.nonce} was already consumed`); throw error; }
  try { await handle.writeFile(bytes); } finally { await handle.close(); }
  return { ...record, path: destination, sha256: sha256(bytes) };
}

export async function authorizeSignedRemoteTime({ trustBundleBytes, trustRootPublicKeyBytes, product, evaluationId, timeAttestationBytes, nonce, ledgerRoot }) {
  if (!/^[a-f0-9]{64}$/.test(nonce ?? "")) throw new Error("time nonce must be 32-byte lowercase hex");
  bounded(evaluationId, "evaluationId");
  const bootstrap = verifyTrustBundleEnvelopeSignature(trustBundleBytes, trustRootPublicKeyBytes, { product });
  const envelope = JSON.parse(Buffer.from(timeAttestationBytes).toString("utf8"));
  if (!/^[a-f0-9]{64}$/.test(envelope?.keyId ?? "")) throw new Error("time attestation lacks a valid keyId");
  const authority = trustedRoleKey(bootstrap, "time-authority", envelope.keyId);
  const verified = verifyTimeAttestationEnvelope(timeAttestationBytes, authority.bytes, { product: bootstrap.payload.product, environment: bootstrap.payload.environment, evaluationId, nonce });
  const trustBundle = verifyTrustBundleEnvelope(trustBundleBytes, trustRootPublicKeyBytes, { product, now: verified.payload.observedAt });
  const consumption = await consumeTimeAttestation(ledgerRoot, verified, evaluationId);
  return { trustBundle, verified, consumption, clock: { ...verified.clock, consumptionSha256: consumption.sha256 } };
}

export async function authorizeLiveRemoteTime({ trustBundleBytes, trustRootPublicKeyBytes, product, evaluationId, authorityClient, ledgerRoot, timeoutMs = 10_000 }) {
  bounded(authorityClient, "time authority client", 4096); bounded(evaluationId, "evaluationId");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) throw new Error("time authority timeout is invalid");
  const bootstrap = verifyTrustBundleEnvelopeSignature(trustBundleBytes, trustRootPublicKeyBytes, { product }); const nonce = randomBytes(32).toString("hex"); const verifierRunId = randomBytes(32).toString("hex");
  const request = { format: TIME_REQUEST_FORMAT, schemaVersion: 1, product: bootstrap.payload.product, environment: bootstrap.payload.environment, evaluationId, nonce, verifierRunId };
  const result = spawnSync(path.resolve(authorityClient), [], { input: canonical(request), encoding: null, timeout: timeoutMs, maxBuffer: 64 * 1024, stdio: ["pipe", "pipe", "pipe"], env: { PATH: process.env.PATH ?? "", REA_TIME_REQUEST_FORMAT: TIME_REQUEST_FORMAT } });
  if (result.error?.code === "ETIMEDOUT" || result.signal) throw new Error("live time authority client timed out");
  if (result.error) throw new Error(`live time authority client failed: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`live time authority client rejected request: ${Buffer.from(result.stderr ?? []).toString("utf8").slice(0, 512)}`);
  const responseBytes = Buffer.from(result.stdout ?? []); if (responseBytes.length === 0 || responseBytes.length > 64 * 1024) throw new Error("live time authority response size is invalid");
  const envelope = JSON.parse(responseBytes.toString("utf8")); if (!/^[a-f0-9]{64}$/.test(envelope?.keyId ?? "")) throw new Error("live time authority response lacks a valid keyId");
  const authority = trustedRoleKey(bootstrap, "time-authority", envelope.keyId); const verified = verifyTimeAttestationEnvelope(responseBytes, authority.bytes, { product: request.product, environment: request.environment, evaluationId, nonce });
  const trustBundle = verifyTrustBundleEnvelope(trustBundleBytes, trustRootPublicKeyBytes, { product, now: verified.payload.observedAt }); const consumption = await consumeTimeAttestation(ledgerRoot, verified, evaluationId);
  return { trustBundle, verified, consumption, request: { ...request, sha256: sha256(canonical(request)) }, clock: { ...verified.clock, source: "signed-live", consumptionSha256: consumption.sha256, verifierRunId, requestSha256: sha256(canonical(request)) } };
}

function usage(message) { if (message) process.stderr.write(`${message}\n`); process.stderr.write("usage: time-attestation.mjs issue --product NAME --environment NAME --evaluation-id ID --nonce HEX --private-key PEM --out NEW.json\n"); process.exit(64); }
function args(argv) { const mode = argv.shift(); if (mode !== "issue") usage("mode must be issue"); const value = {}; for (let index = 0; index < argv.length; index += 2) { const key = argv[index]; const item = argv[index + 1]; if (!key?.startsWith("--") || item === undefined || value[key.slice(2)] !== undefined) usage("invalid arguments"); value[key.slice(2)] = item; } for (const name of ["product", "environment", "evaluation-id", "nonce", "private-key", "out"]) if (!value[name]) usage(`--${name} is required`); return value; }
async function main() {
  const options = args(process.argv.slice(2)); if (!/^[a-f0-9]{64}$/.test(options.nonce)) usage("--nonce must be 32-byte lowercase hex"); const observedAt = new Date().toISOString();
  const payload = { schemaVersion: 1, product: options.product, environment: options.environment, evaluationId: options["evaluation-id"], nonce: options.nonce, authorityRunId: randomBytes(32).toString("hex"), observedAt };
  const envelope = createTimeAttestationEnvelope(payload, { key: await readFile(path.resolve(options["private-key"])), passphrase: process.env.REA_TIME_AUTHORITY_PASSPHRASE }); const serialized = `${JSON.stringify(envelope, null, 2)}\n`; const handle = await open(path.resolve(options.out), "wx", 0o644); try { await handle.writeFile(serialized); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: "issued", observedAt, nonce: payload.nonce, authorityRunId: payload.authorityRunId, sha256: sha256(Buffer.from(serialized)), out: path.resolve(options.out) }, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`time attestation error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
