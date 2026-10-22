#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { resolveTrustedTime } from "./trusted-time.mjs";

export const TRUST_BUNDLE_FORMAT = "rea-hardening-trust-bundle/v1";
export const TRUST_ROLES = Object.freeze([
  "artifact-publisher",
  "assessment-gate",
  "evidence-coordinator",
  "evidence-worker",
  "product-builder",
  "protection-policy",
  "release-attestation",
  "release-manifest",
  "server-authorization",
  "time-authority",
]);
const ROLE_SET = new Set(TRUST_ROLES);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
}
function bounded(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function instant(value, label) {
  const result = Date.parse(value);
  if (!Number.isFinite(result) || new Date(result).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`);
  return result;
}
function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  return value;
}
function canonical(value) { return Buffer.from(JSON.stringify(canonicalValue(value))); }
function publicIdentity(bytes, label) {
  const key = bytes?.type === "public" ? bytes : createPublicKey(bytes);
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be Ed25519`);
  const der = key.export({ type: "spki", format: "der" });
  return { key, der, keyId: sha256(der), spki: der.toString("base64") };
}
function validatePayload(payload, nowValue = Date.now(), skipTimeWindow = false) {
  exactKeys(payload, ["bundleId", "environment", "expiresAt", "issuedAt", "product", "roles", "schemaVersion"], "trust bundle payload");
  if (payload.schemaVersion !== 1) throw new Error("trust bundle schemaVersion must be 1");
  bounded(payload.bundleId, "bundleId"); bounded(payload.product, "product"); bounded(payload.environment, "environment");
  const issuedAt = instant(payload.issuedAt, "issuedAt"); const expiresAt = instant(payload.expiresAt, "expiresAt");
  if (expiresAt <= issuedAt || expiresAt > issuedAt + 366 * 24 * 60 * 60 * 1000 || (!skipTimeWindow && (issuedAt > nowValue + 5 * 60 * 1000 || expiresAt <= nowValue))) throw new Error("trust bundle validity window is invalid or expired");
  if (!payload.roles || typeof payload.roles !== "object" || Array.isArray(payload.roles)) throw new Error("trust bundle roles must be an object");
  const roleNames = Object.keys(payload.roles).sort();
  if (roleNames.length === 0 || roleNames.some((role) => !ROLE_SET.has(role))) throw new Error("trust bundle contains an unknown or empty role inventory");
  const globalKeyIds = new Map();
  for (const role of roleNames) {
    const entries = payload.roles[role];
    if (!Array.isArray(entries) || entries.length === 0) throw new Error(`trust bundle role ${role} must contain at least one key`);
    const roleIds = new Set();
    for (const [index, entry] of entries.entries()) {
      exactKeys(entry, ["keyId", "publicKeySpkiBase64"], `roles.${role}[${index}]`);
      if (!/^[a-f0-9]{64}$/.test(entry.keyId ?? "") || typeof entry.publicKeySpkiBase64 !== "string") throw new Error(`roles.${role}[${index}] is invalid`);
      const der = Buffer.from(entry.publicKeySpkiBase64, "base64");
      const identity = publicIdentity({ key: der, type: "spki", format: "der" }, `roles.${role}[${index}] public key`);
      if (identity.keyId !== entry.keyId || identity.spki !== entry.publicKeySpkiBase64) throw new Error(`roles.${role}[${index}] key identity mismatch`);
      if (roleIds.has(entry.keyId)) throw new Error(`trust bundle role ${role} contains a duplicate key`);
      roleIds.add(entry.keyId);
      const priorRole = globalKeyIds.get(entry.keyId);
      if (priorRole && priorRole !== role) throw new Error(`trust bundle key ${entry.keyId} is reused across roles ${priorRole} and ${role}`);
      globalKeyIds.set(entry.keyId, role);
    }
    entries.sort((left, right) => left.keyId.localeCompare(right.keyId));
  }
  return payload;
}

export function createTrustBundleEnvelope(payloadValue, rootPrivateKeyBytes, nowValue = Date.now()) {
  const payload = validatePayload(structuredClone(payloadValue), nowValue);
  const privateKey = rootPrivateKeyBytes?.type === "private" ? rootPrivateKeyBytes : createPrivateKey({ key: rootPrivateKeyBytes, passphrase: process.env.REA_TRUST_ROOT_PASSPHRASE });
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("trust root private key must be Ed25519");
  const root = publicIdentity(createPublicKey(privateKey), "trust root public key");
  const payloadBytes = canonical(payload);
  return {
    format: TRUST_BUNDLE_FORMAT,
    keyId: root.keyId,
    payload: payloadBytes.toString("base64"),
    signature: sign(null, Buffer.concat([Buffer.from(`${TRUST_BUNDLE_FORMAT}\0`), payloadBytes]), privateKey).toString("base64"),
  };
}

export function verifyTrustBundleEnvelopeSignature(envelopeBytes, rootPublicKeyBytes, { product = null } = {}) {
  const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8"));
  exactKeys(envelope, ["format", "keyId", "payload", "signature"], "trust bundle envelope");
  if (envelope.format !== TRUST_BUNDLE_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("trust bundle envelope is invalid");
  const root = publicIdentity(rootPublicKeyBytes, "trust root public key");
  if (root.keyId !== envelope.keyId) throw new Error("trust bundle root key is not pinned");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${TRUST_BUNDLE_FORMAT}\0`), payloadBytes]), root.key, Buffer.from(envelope.signature, "base64"))) throw new Error("trust bundle signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  if (!canonical(payload).equals(payloadBytes)) throw new Error("trust bundle payload is not canonical");
  validatePayload(payload, 0, true);
  if (product !== null && payload.product !== product) throw new Error("trust bundle product mismatch");
  return { format: envelope.format, rootKeyId: envelope.keyId, envelopeSha256: sha256(Buffer.from(envelopeBytes)), payload };
}

export function verifyTrustBundleEnvelope(envelopeBytes, rootPublicKeyBytes, { product = null, now = null } = {}) {
  const verified = verifyTrustBundleEnvelopeSignature(envelopeBytes, rootPublicKeyBytes, { product });
  validatePayload(verified.payload, now === null ? Date.now() : instant(now, "now"));
  return verified;
}

export function trustedRoleKey(bundle, role, expectedKeyId = null) {
  if (!ROLE_SET.has(role)) throw new Error(`unknown trust role: ${role}`);
  const entries = bundle?.payload?.roles?.[role];
  if (!Array.isArray(entries) || entries.length === 0) throw new Error(`trust bundle lacks required role: ${role}`);
  const entry = expectedKeyId === null ? (entries.length === 1 ? entries[0] : null) : entries.find((candidate) => candidate.keyId === expectedKeyId);
  if (!entry) throw new Error(expectedKeyId === null ? `trust bundle role ${role} is ambiguous` : `key ${expectedKeyId} is not trusted for role ${role}`);
  const key = createPublicKey({ key: Buffer.from(entry.publicKeySpkiBase64, "base64"), type: "spki", format: "der" });
  return { keyId: entry.keyId, bytes: Buffer.from(key.export({ type: "spki", format: "pem" })) };
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage:\n  trust-bundle.mjs sign --descriptor PAYLOAD.json --private-key ROOT.pem --out NEW.json\n  trust-bundle.mjs verify --bundle SIGNED.json --root-public-key ROOT.pem [--product NAME] [--now ISO]\n");
  process.exit(64);
}
function args(argv) {
  const mode = argv.shift(); if (!new Set(["sign", "verify"]).has(mode)) usage("mode must be sign or verify");
  const options = { mode };
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || options[key.slice(2)] !== undefined) usage("invalid arguments");
    options[key.slice(2)] = value;
  }
  const required = mode === "sign" ? ["descriptor", "private-key", "out"] : ["bundle", "root-public-key"];
  for (const name of required) if (!options[name]) usage(`--${name} is required`);
  return options;
}
async function signDescriptor(options) {
  const descriptorPath = path.resolve(options.descriptor); const descriptor = JSON.parse(await readFile(descriptorPath, "utf8"));
  exactKeys(descriptor, ["bundleId", "environment", "expiresAt", "issuedAt", "product", "roles", "schemaVersion"], "trust bundle descriptor");
  const roles = {};
  for (const [role, files] of Object.entries(descriptor.roles ?? {})) {
    if (!ROLE_SET.has(role) || !Array.isArray(files) || files.length === 0 || files.some((file) => typeof file !== "string" || !file)) throw new Error(`descriptor role ${role} is invalid`);
    roles[role] = [];
    for (const file of files) {
      const identity = publicIdentity(await readFile(path.resolve(path.dirname(descriptorPath), file)), `descriptor role ${role} key`);
      roles[role].push({ keyId: identity.keyId, publicKeySpkiBase64: identity.spki });
    }
  }
  const envelope = createTrustBundleEnvelope({ ...descriptor, roles }, await readFile(path.resolve(options["private-key"])), Date.now());
  const handle = await open(path.resolve(options.out), "wx", 0o644); try { await handle.writeFile(`${JSON.stringify(envelope, null, 2)}\n`); } finally { await handle.close(); }
  return { status: "signed", bundleId: descriptor.bundleId, product: descriptor.product, rootKeyId: envelope.keyId, out: path.resolve(options.out) };
}
async function main() {
  const options = args(process.argv.slice(2));
  const result = options.mode === "sign" ? await signDescriptor(options) : verifyTrustBundleEnvelope(await readFile(path.resolve(options.bundle)), await readFile(path.resolve(options["root-public-key"])), { product: options.product ?? null, now: resolveTrustedTime(options.now ?? null).observedAt });
  process.stdout.write(`${JSON.stringify(options.mode === "verify" ? { status: "verified", bundleId: result.payload.bundleId, product: result.payload.product, environment: result.payload.environment, rootKeyId: result.rootKeyId, sha256: result.envelopeSha256, roles: Object.keys(result.payload.roles).sort() } : result, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`trust bundle error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
