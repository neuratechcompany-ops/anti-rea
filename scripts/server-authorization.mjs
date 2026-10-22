#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { verifyEvidenceChallenge } from "./evidence-challenge.mjs";
import { verifyProtectionPolicyEnvelope } from "./protection-policy.mjs";
import { trustedRoleKey, verifyTrustBundleEnvelope } from "./trust-bundle.mjs";

export const SERVER_AUTHORIZATION_FORMAT = "rea-hardening-server-authorization/v2";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));

function fail(message) { throw new Error(message); }
function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) fail(`${label} fields are invalid`);
}
function instant(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) fail(`${label} must be canonical ISO-8601`);
  return milliseconds;
}
function envelopeKeyId(bytes, label) {
  const envelope = JSON.parse(Buffer.from(bytes).toString("utf8"));
  if (!/^[a-f0-9]{64}$/.test(envelope?.keyId ?? "")) fail(`${label} lacks a valid keyId`);
  return envelope.keyId;
}
function args(argv) {
  if (argv.shift() !== "sign") fail("mode must be sign");
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) fail("invalid arguments");
    result[key.slice(2)] = value;
  }
  for (const name of ["transcript", "transcript-schema", "protection-policy", "trust-bundle", "trust-root-public-key", "challenge", "private-key", "expires-at", "out"]) if (!result[name]) fail(`--${name} is required`);
  return result;
}
function validateTranscript(transcript, policy) {
  exactKeys(transcript, ["action", "channel", "configSha256", "deploymentSha256", "environment", "product", "scenarios", "schemaVersion"], "transcript");
  if (transcript.schemaVersion !== 1) fail("transcript schemaVersion is invalid");
  for (const name of ["environment", "channel", "action", "deploymentSha256", "configSha256"]) if (transcript[name] !== policy.serverAuthorization[name]) fail(`transcript ${name} differs from owner policy`);
  if (transcript.product !== policy.product) fail("transcript product differs from owner policy");
  if (!Array.isArray(transcript.scenarios) || transcript.scenarios.length !== 2) fail("transcript requires exactly two scenarios");
  const names = new Set();
  for (const [index, scenario] of transcript.scenarios.entries()) {
    exactKeys(scenario, ["clientDecision", "httpStatus", "mutation", "name", "requestSha256", "responseSha256", "serverDecision"], `scenario[${index}]`);
    if (typeof scenario.name !== "string" || names.has(scenario.name) || typeof scenario.mutation !== "string" || !new Set(["allowed", "denied"]).has(scenario.clientDecision) || !new Set(["allowed", "denied"]).has(scenario.serverDecision) || !Number.isSafeInteger(scenario.httpStatus) || !/^[a-f0-9]{64}$/.test(scenario.requestSha256 ?? "") || !/^[a-f0-9]{64}$/.test(scenario.responseSha256 ?? "")) fail(`scenario[${index}] is invalid`);
    names.add(scenario.name);
  }
  const legitimate = transcript.scenarios.find((item) => item.name === "legitimate-client");
  const patched = transcript.scenarios.find((item) => item.name === "patched-favorable-client");
  if (!legitimate || legitimate.clientDecision !== "allowed" || legitimate.serverDecision !== "allowed" || legitimate.httpStatus < 200 || legitimate.httpStatus >= 300) fail("legitimate scenario did not succeed");
  if (!patched || patched.clientDecision !== "allowed" || patched.serverDecision !== "denied" || patched.httpStatus < 400 || typeof patched.mutation !== "string" || !patched.mutation.trim()) fail("patched favorable client was not independently denied");
}

async function main() {
  const options = args(process.argv.slice(2)); const now = new Date().toISOString();
  const trustBytes = await readFile(path.resolve(options["trust-bundle"]));
  const trust = verifyTrustBundleEnvelope(trustBytes, await readFile(path.resolve(options["trust-root-public-key"])), { now });
  const policyBytes = await readFile(path.resolve(options["protection-policy"]));
  const policy = verifyProtectionPolicyEnvelope(policyBytes, trustedRoleKey(trust, "protection-policy", envelopeKeyId(policyBytes, "protection policy")).bytes, now);
  if (trust.payload.product !== policy.payload.product) fail("trust bundle product differs from owner policy");
  const transcriptBytes = await readFile(path.resolve(options.transcript));
  const transcript = JSON.parse(transcriptBytes.toString("utf8")); validateTranscript(transcript, policy.payload);
  const schemaBytes = await readFile(path.resolve(options["transcript-schema"]));
  if (sha256(schemaBytes) !== policy.payload.serverAuthorization.transcriptSchemaSha256) fail("transcript schema differs from owner policy");
  const privateKey = createPrivateKey({ key: await readFile(path.resolve(options["private-key"])), passphrase: process.env.REA_SERVER_AUTHORIZATION_PASSPHRASE });
  if (privateKey.asymmetricKeyType !== "ed25519") fail("server authorization private key must be Ed25519");
  const keyId = sha256(createPublicKey(privateKey).export({ type: "spki", format: "der" }));
  trustedRoleKey(trust, "server-authorization", keyId);
  const challengeBytes = await readFile(path.resolve(options.challenge));
  const challenge = verifyEvidenceChallenge(challengeBytes, trustedRoleKey(trust, "evidence-coordinator", envelopeKeyId(challengeBytes, "challenge")).bytes, { product: policy.payload.product, policySha256: policy.envelopeSha256, kind: "server-authorization", workerKeyId: keyId }, now);
  const expiresAt = new Date(instant(options["expires-at"], "expiresAt")).toISOString();
  if (Date.parse(expiresAt) <= Date.parse(now) || Date.parse(expiresAt) > Date.parse(now) + 24 * 60 * 60 * 1000) fail("receipt validity must be positive and at most 24 hours");
  const payload = { schemaVersion: 2, product: policy.payload.product, artifactSha256: challenge.payload.artifactSha256, ...policy.payload.serverAuthorization, transcriptSha256: sha256(transcriptBytes), challengeId: challenge.payload.challengeId, challengeSha256: challenge.envelopeSha256, issuedAt: now, expiresAt };
  const payloadBytes = canonical(payload);
  const envelope = { format: SERVER_AUTHORIZATION_FORMAT, keyId, payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${SERVER_AUTHORIZATION_FORMAT}\0`), payloadBytes]), privateKey).toString("base64") };
  const serialized = `${JSON.stringify(envelope, null, 2)}\n`; const handle = await open(path.resolve(options.out), "wx", 0o644);
  try { await handle.writeFile(serialized); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: "signed", product: payload.product, channel: payload.channel, action: payload.action, challengeId: payload.challengeId, sha256: sha256(Buffer.from(serialized)), out: path.resolve(options.out) }, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`server authorization error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
