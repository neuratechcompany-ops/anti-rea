#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const EVIDENCE_CHALLENGE_FORMAT = "rea-hardening-evidence-challenge/v1";
export const EVIDENCE_CONSUMPTION_FORMAT = "rea-hardening-evidence-consumption/v1";
const KINDS = new Set(["analyzer-probe", "adversarial-probe", "server-authorization"]);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
}
function digest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} must be lowercase SHA-256 hex`);
  return value;
}
function bounded(value, label, maximum = 256) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function instant(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`);
  return milliseconds;
}

export function createEvidenceChallengeEnvelope(payload, privateKeyValue) {
  exactKeys(payload, ["artifactSha256", "challengeId", "environmentSha256", "evaluationId", "expiresAt", "issuedAt", "kind", "policySha256", "product", "runnerId", "schemaVersion", "workerKeyId", "workloadIdentity"], "challenge payload");
  if (payload.schemaVersion !== 1 || !KINDS.has(payload.kind)) throw new Error("challenge payload identity is invalid");
  for (const name of ["artifactSha256", "environmentSha256", "policySha256", "workerKeyId"]) digest(payload[name], name);
  if (!/^[a-f0-9]{64}$/.test(payload.challengeId ?? "")) throw new Error("challengeId is invalid");
  bounded(payload.product, "product", 128); bounded(payload.evaluationId, "evaluationId", 128); bounded(payload.runnerId, "runnerId", 128); bounded(payload.workloadIdentity, "workloadIdentity", 512);
  const issuedAt = instant(payload.issuedAt, "issuedAt"); const expiresAt = instant(payload.expiresAt, "expiresAt");
  if (expiresAt <= issuedAt || expiresAt > issuedAt + 15 * 60 * 1000) throw new Error("challenge validity window must be at most 15 minutes");
  const privateKey = privateKeyValue?.type === "private" ? privateKeyValue : createPrivateKey(privateKeyValue);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("evidence coordinator private key must be Ed25519");
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" }); const payloadBytes = canonical(payload);
  return { format: EVIDENCE_CHALLENGE_FORMAT, keyId: sha256(publicDer), payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${EVIDENCE_CHALLENGE_FORMAT}\0`), payloadBytes]), privateKey).toString("base64") };
}

export function verifyEvidenceChallenge(envelopeBytes, publicKeyBytes, expected = {}, nowValue = null) {
  const bytes = Buffer.from(envelopeBytes); const envelope = JSON.parse(bytes.toString("utf8"));
  exactKeys(envelope, ["format", "keyId", "payload", "signature"], "challenge envelope");
  if (envelope.format !== EVIDENCE_CHALLENGE_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("challenge envelope is invalid");
  const publicKey = publicKeyBytes?.type === "public" ? publicKeyBytes : createPublicKey(publicKeyBytes); if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("evidence coordinator public key must be Ed25519");
  if (sha256(publicKey.export({ type: "spki", format: "der" })) !== envelope.keyId) throw new Error("evidence coordinator key is not trusted");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${EVIDENCE_CHALLENGE_FORMAT}\0`), payloadBytes]), publicKey, Buffer.from(envelope.signature, "base64"))) throw new Error("evidence challenge signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  if (!canonical(payload).equals(payloadBytes)) throw new Error("evidence challenge payload is not canonical");
  exactKeys(payload, ["artifactSha256", "challengeId", "environmentSha256", "evaluationId", "expiresAt", "issuedAt", "kind", "policySha256", "product", "runnerId", "schemaVersion", "workerKeyId", "workloadIdentity"], "challenge payload");
  if (payload.schemaVersion !== 1 || !KINDS.has(payload.kind) || !/^[a-f0-9]{64}$/.test(payload.challengeId ?? "")) throw new Error("challenge payload identity is invalid");
  for (const name of ["artifactSha256", "environmentSha256", "policySha256", "workerKeyId"]) digest(payload[name], name);
  bounded(payload.product, "product", 128); bounded(payload.evaluationId, "evaluationId", 128); bounded(payload.runnerId, "runnerId", 128); bounded(payload.workloadIdentity, "workloadIdentity", 512);
  const issuedAt = instant(payload.issuedAt, "issuedAt"); const expiresAt = instant(payload.expiresAt, "expiresAt"); const now = nowValue === null ? Date.now() : instant(nowValue, "now");
  if (issuedAt > now + 60 * 1000 || expiresAt <= now || expiresAt > issuedAt + 15 * 60 * 1000) throw new Error("evidence challenge is stale or has an invalid validity window");
  for (const [name, value] of Object.entries(expected)) if (value !== undefined && payload[name] !== value) throw new Error(`evidence challenge ${name} mismatch`);
  return { keyId: envelope.keyId, envelopeSha256: sha256(bytes), payload };
}

export async function consumeEvidenceChallenge(ledgerRootValue, verifiedChallenge, evaluationId, consumedAt = new Date().toISOString()) {
  bounded(evaluationId, "evaluationId", 128);
  if (verifiedChallenge.payload.evaluationId !== evaluationId) throw new Error("evidence challenge evaluationId mismatch");
  const ledgerRoot = await realpath(path.resolve(ledgerRootValue));
  if (!(await lstat(ledgerRoot)).isDirectory()) throw new Error("evidence challenge ledger must be a directory");
  instant(consumedAt, "consumedAt");
  const record = { format: EVIDENCE_CONSUMPTION_FORMAT, schemaVersion: 1, challengeId: verifiedChallenge.payload.challengeId, challengeSha256: verifiedChallenge.envelopeSha256, evaluationId, consumedAt };
  const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`); const destination = path.join(ledgerRoot, `${record.challengeId}.json`);
  let handle;
  try { handle = await open(destination, "wx", 0o444); }
  catch (error) { if (error?.code === "EEXIST") throw new Error(`evidence challenge ${record.challengeId} was already consumed`); throw error; }
  try { await handle.writeFile(bytes); } finally { await handle.close(); }
  return { ...record, path: destination, sha256: sha256(bytes) };
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: evidence-challenge.mjs issue --product NAME --evaluation-id ID --policy-sha256 HEX --artifact-sha256 HEX --kind analyzer-probe|adversarial-probe|server-authorization --worker-key-id HEX --runner-id ID --environment-sha256 HEX --workload-identity ID --private-key PEM --expires-at ISO --out NEW.json\n");
  process.exit(64);
}
function args(argv) {
  const mode = argv.shift(); if (mode !== "issue") usage("mode must be issue"); const result = {};
  for (let index = 0; index < argv.length; index += 2) { const key = argv[index]; const value = argv[index + 1]; if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) usage("invalid arguments"); result[key.slice(2)] = value; }
  for (const name of ["product", "evaluation-id", "policy-sha256", "artifact-sha256", "kind", "worker-key-id", "runner-id", "environment-sha256", "workload-identity", "private-key", "expires-at", "out"]) if (!result[name]) usage(`--${name} is required`);
  if (!KINDS.has(result.kind)) usage("--kind is invalid"); return result;
}
async function main() {
  const options = args(process.argv.slice(2)); const issuedAt = new Date().toISOString(); const expiresAt = new Date(instant(options["expires-at"], "expires-at")).toISOString();
  const payload = { schemaVersion: 1, challengeId: randomBytes(32).toString("hex"), product: options.product, evaluationId: options["evaluation-id"], policySha256: options["policy-sha256"], artifactSha256: options["artifact-sha256"], kind: options.kind, workerKeyId: options["worker-key-id"], runnerId: options["runner-id"], environmentSha256: options["environment-sha256"], workloadIdentity: options["workload-identity"], issuedAt, expiresAt };
  const envelope = createEvidenceChallengeEnvelope(payload, { key: await readFile(path.resolve(options["private-key"])), passphrase: process.env.REA_EVIDENCE_COORDINATOR_PASSPHRASE }); const serialized = `${JSON.stringify(envelope, null, 2)}\n`;
  const handle = await open(path.resolve(options.out), "wx", 0o644); try { await handle.writeFile(serialized); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: "issued", challengeId: payload.challengeId, sha256: sha256(Buffer.from(serialized)), expiresAt, out: path.resolve(options.out) }, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`evidence challenge error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
