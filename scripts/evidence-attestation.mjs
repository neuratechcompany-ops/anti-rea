#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { verifyEvidenceChallenge } from "./evidence-challenge.mjs";

export const EVIDENCE_ATTESTATION_FORMAT = "rea-hardening-evidence-attestation/v2";
const KINDS = new Set(["analyzer-probe", "adversarial-probe"]);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
}
function instant(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`);
  return milliseconds;
}
function bounded(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function reportIdentity(bytes, kind) {
  const report = JSON.parse(Buffer.from(bytes).toString("utf8"));
  const artifactSha256 = kind === "analyzer-probe" ? report?.artifactIdentity?.sha256 : report?.artifact?.sha256;
  if (!/^[a-f0-9]{64}$/.test(artifactSha256 ?? "")) throw new Error("report lacks a valid artifact identity");
  return { reportSha256: sha256(bytes), artifactSha256 };
}

export function verifyEvidenceAttestation(envelopeBytes, publicKeyBytes, expected, nowValue = null) {
  const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8"));
  exactKeys(envelope, ["format", "keyId", "payload", "signature"], "evidence attestation envelope");
  if (envelope.format !== EVIDENCE_ATTESTATION_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("evidence attestation envelope is invalid");
  const publicKey = createPublicKey(publicKeyBytes);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("evidence worker public key must be Ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (sha256(publicDer) !== envelope.keyId) throw new Error("evidence worker key is not trusted");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${EVIDENCE_ATTESTATION_FORMAT}\0`), payloadBytes]), publicKey, Buffer.from(envelope.signature, "base64"))) throw new Error("evidence attestation signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  if (!canonical(payload).equals(payloadBytes)) throw new Error("evidence attestation payload is not canonical");
  exactKeys(payload, ["artifactSha256", "challengeId", "challengeSha256", "environmentSha256", "expiresAt", "issuedAt", "kind", "reportSha256", "runId", "runnerId", "schemaVersion", "workloadIdentity"], "evidence attestation payload");
  if (payload.schemaVersion !== 2 || !KINDS.has(payload.kind) || !/^[a-f0-9]{64}$/.test(payload.reportSha256 ?? "") || !/^[a-f0-9]{64}$/.test(payload.artifactSha256 ?? "") || !/^[a-f0-9]{64}$/.test(payload.challengeId ?? "") || !/^[a-f0-9]{64}$/.test(payload.challengeSha256 ?? "") || !/^[a-f0-9]{64}$/.test(payload.environmentSha256 ?? "")) throw new Error("evidence attestation payload identity is invalid");
  bounded(payload.runId, "runId"); bounded(payload.runnerId, "runnerId"); bounded(payload.workloadIdentity, "workloadIdentity");
  const issuedAt = instant(payload.issuedAt, "issuedAt"); const expiresAt = instant(payload.expiresAt, "expiresAt");
  const now = nowValue === null ? Date.now() : instant(nowValue, "now");
  if (issuedAt > now + 5 * 60 * 1000 || expiresAt <= now || expiresAt > issuedAt + 24 * 60 * 60 * 1000) throw new Error("evidence attestation is stale or has an invalid validity window");
  for (const name of ["kind", "reportSha256", "artifactSha256", "challengeId", "challengeSha256", "runnerId", "environmentSha256", "workloadIdentity"]) if (expected[name] !== undefined && payload[name] !== expected[name]) throw new Error(`evidence attestation ${name} mismatch`);
  return { keyId: envelope.keyId, payload };
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: evidence-attestation.mjs sign --report REPORT.json --kind analyzer-probe|adversarial-probe --challenge SIGNED.json --coordinator-public-key PEM --private-key PEM --run-id ID --expires-at ISO --out NEW.json\n");
  process.exit(64);
}
function args(argv) {
  const mode = argv.shift(); if (mode !== "sign") usage("mode must be sign");
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) usage("invalid arguments");
    result[key.slice(2)] = value;
  }
  for (const name of ["report", "kind", "challenge", "coordinator-public-key", "private-key", "run-id", "expires-at", "out"]) if (!result[name]) usage(`--${name} is required`);
  if (!KINDS.has(result.kind)) usage("--kind is invalid");
  return result;
}

async function main() {
  const options = args(process.argv.slice(2));
  const reportBytes = await readFile(path.resolve(options.report));
  const identity = reportIdentity(reportBytes, options.kind);
  const issuedAt = new Date().toISOString(); const expiresAt = instant(options["expires-at"], "expires-at");
  if (expiresAt <= Date.now() || expiresAt > Date.now() + 24 * 60 * 60 * 1000) throw new Error("expires-at must be within the next 24 hours");
  const privateKey = createPrivateKey({ key: await readFile(path.resolve(options["private-key"])), passphrase: process.env.REA_EVIDENCE_WORKER_PASSPHRASE });
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("evidence worker private key must be Ed25519");
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const challengeBytes = await readFile(path.resolve(options.challenge));
  const challenge = verifyEvidenceChallenge(challengeBytes, await readFile(path.resolve(options["coordinator-public-key"])), { kind: options.kind, artifactSha256: identity.artifactSha256, workerKeyId: sha256(publicDer) });
  if (expiresAt > Date.parse(challenge.payload.expiresAt)) throw new Error("evidence attestation cannot outlive its challenge");
  const challengeBinding = { challengeId: challenge.payload.challengeId, challengeSha256: challenge.envelopeSha256, runnerId: challenge.payload.runnerId, environmentSha256: challenge.payload.environmentSha256, workloadIdentity: challenge.payload.workloadIdentity };
  const payload = { schemaVersion: 2, kind: options.kind, runId: bounded(options["run-id"], "runId"), issuedAt, expiresAt: new Date(expiresAt).toISOString(), ...identity, ...challengeBinding };
  const payloadBytes = canonical(payload);
  const envelope = { format: EVIDENCE_ATTESTATION_FORMAT, keyId: sha256(publicDer), payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${EVIDENCE_ATTESTATION_FORMAT}\0`), payloadBytes]), privateKey).toString("base64") };
  const handle = await open(path.resolve(options.out), "wx", 0o644);
  try { await handle.writeFile(`${JSON.stringify(envelope, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: "signed", keyId: envelope.keyId, reportSha256: identity.reportSha256, artifactSha256: identity.artifactSha256, out: path.resolve(options.out) }, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => {
  process.stderr.write(`evidence attestation error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
