#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { open, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const REGRESSION_REPORT_FORMAT = "rea-hardening-regression-report/v1";
export const REGRESSION_ATTESTATION_FORMAT = "rea-hardening-regression-attestation/v1";
const KINDS = new Set(["functional", "performance", "platform-security"]);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
}
function digest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} must be lowercase SHA-256 hex`);
  return value;
}
function bounded(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function instant(value, label) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be canonical ISO-8601`);
  return milliseconds;
}
async function currentFileIdentity(value, expectedSha256, label) {
  const file = await realpath(path.resolve(value));
  const bytes = await readFile(file);
  if (sha256(bytes) !== expectedSha256) throw new Error(`${label} no longer matches its digest`);
  return { file, bytes };
}

export async function validateRegressionReport(report, expected = null) {
  exactKeys(report, ["artifactSha256", "completedAt", "format", "kind", "result", "runner", "schemaVersion", "startedAt", "status", "suite", "summary"], "regression report");
  if (report.format !== REGRESSION_REPORT_FORMAT || report.schemaVersion !== 1 || !KINDS.has(report.kind) || report.status !== "passed") throw new Error("regression report identity or status is invalid");
  digest(report.artifactSha256, "artifactSha256");
  const startedAt = instant(report.startedAt, "startedAt"); const completedAt = instant(report.completedAt, "completedAt");
  if (completedAt < startedAt || completedAt > startedAt + 24 * 60 * 60 * 1000) throw new Error("regression report execution window is invalid");

  exactKeys(report.suite, ["id", "path", "sha256"], "suite");
  bounded(report.suite.id, "suite.id"); digest(report.suite.sha256, "suite.sha256");
  await currentFileIdentity(report.suite.path, report.suite.sha256, "suite");
  exactKeys(report.runner, ["environmentSha256", "executablePath", "executableSha256", "id"], "runner");
  bounded(report.runner.id, "runner.id"); digest(report.runner.executableSha256, "runner.executableSha256"); digest(report.runner.environmentSha256, "runner.environmentSha256");
  await currentFileIdentity(report.runner.executablePath, report.runner.executableSha256, "runner executable");
  exactKeys(report.result, ["bytes", "path", "sha256"], "result");
  digest(report.result.sha256, "result.sha256");
  if (!Number.isSafeInteger(report.result.bytes) || report.result.bytes < 1 || report.result.bytes > 64 * 1024 * 1024) throw new Error("result.bytes is invalid");
  const rawResult = await currentFileIdentity(report.result.path, report.result.sha256, "raw result");
  if (rawResult.bytes.length !== report.result.bytes) throw new Error("raw result byte length mismatch");

  if (report.kind === "performance") {
    exactKeys(report.summary, ["metrics"], "performance summary");
    if (!Array.isArray(report.summary.metrics) || report.summary.metrics.length === 0) throw new Error("performance summary requires metrics");
    const ids = new Set();
    for (const [index, metric] of report.summary.metrics.entries()) {
      exactKeys(metric, ["id", "maximum", "unit", "value"], `metrics[${index}]`);
      bounded(metric.id, `metrics[${index}].id`); bounded(metric.unit, `metrics[${index}].unit`);
      if (ids.has(metric.id)) throw new Error("performance metric IDs must be unique");
      ids.add(metric.id);
      if (!Number.isFinite(metric.value) || !Number.isFinite(metric.maximum) || metric.value < 0 || metric.maximum < 0 || metric.value > metric.maximum) throw new Error(`performance metric ${metric.id} exceeds its budget or is invalid`);
    }
  } else {
    exactKeys(report.summary, ["failed", "passed", "skipped", "total"], `${report.kind} summary`);
    for (const name of ["total", "passed", "failed", "skipped"]) if (!Number.isSafeInteger(report.summary[name]) || report.summary[name] < 0) throw new Error(`${report.kind} summary.${name} is invalid`);
    if (report.summary.total < 1 || report.summary.failed !== 0 || report.summary.passed < 1 || report.summary.total !== report.summary.passed + report.summary.failed + report.summary.skipped) throw new Error(`${report.kind} regression did not pass`);
  }
  if (expected) {
    for (const [actual, wanted, label] of [
      [report.artifactSha256, expected.artifactSha256, "artifact"],
      [report.kind, expected.kind, "kind"],
      [report.suite.id, expected.suiteId, "suite ID"],
      [report.suite.sha256, expected.suiteSha256, "suite digest"],
      [report.runner.id, expected.runnerId, "runner ID"],
      [report.runner.executableSha256, expected.runnerExecutableSha256, "runner executable digest"],
      [report.runner.environmentSha256, expected.environmentSha256, "runner environment digest"],
    ]) if (actual !== wanted) throw new Error(`regression report ${label} mismatch`);
  }
  return report;
}

export async function verifyRegressionAttestation(envelopeBytes, reportBytes, publicKeyBytes, expected, nowValue = null) {
  const report = JSON.parse(Buffer.from(reportBytes).toString("utf8"));
  await validateRegressionReport(report, expected);
  const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8"));
  exactKeys(envelope, ["format", "keyId", "payload", "signature"], "regression attestation envelope");
  if (envelope.format !== REGRESSION_ATTESTATION_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "") || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") throw new Error("regression attestation envelope is invalid");
  const publicKey = createPublicKey(publicKeyBytes);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("regression worker public key must be Ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (sha256(publicDer) !== envelope.keyId) throw new Error("regression worker key is not trusted");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${REGRESSION_ATTESTATION_FORMAT}\0`), payloadBytes]), publicKey, Buffer.from(envelope.signature, "base64"))) throw new Error("regression attestation signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  if (!canonical(payload).equals(payloadBytes)) throw new Error("regression attestation payload is not canonical");
  exactKeys(payload, ["artifactSha256", "environmentSha256", "expiresAt", "issuedAt", "kind", "reportSha256", "runId", "runnerExecutableSha256", "runnerId", "schemaVersion", "suiteId", "suiteSha256"], "regression attestation payload");
  if (payload.schemaVersion !== 1) throw new Error("regression attestation schema is unsupported");
  bounded(payload.runId, "runId");
  const issuedAt = instant(payload.issuedAt, "issuedAt"); const expiresAt = instant(payload.expiresAt, "expiresAt");
  const now = nowValue === null ? Date.now() : instant(nowValue, "now");
  if (issuedAt > now + 5 * 60 * 1000 || expiresAt <= now || expiresAt > issuedAt + 24 * 60 * 60 * 1000) throw new Error("regression attestation is stale or has an invalid validity window");
  const expectedPayload = {
    reportSha256: sha256(reportBytes), artifactSha256: report.artifactSha256, kind: report.kind,
    suiteId: report.suite.id, suiteSha256: report.suite.sha256, runnerId: report.runner.id,
    runnerExecutableSha256: report.runner.executableSha256, environmentSha256: report.runner.environmentSha256,
  };
  for (const [name, value] of Object.entries(expectedPayload)) if (payload[name] !== value) throw new Error(`regression attestation ${name} mismatch`);
  return { keyId: envelope.keyId, payload, report };
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: regression-attestation.mjs sign --report REPORT.json --private-key PEM --run-id ID --expires-at ISO --out NEW.json\n");
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
  for (const name of ["report", "private-key", "run-id", "expires-at", "out"]) if (!options[name]) usage(`--${name} is required`);
  return options;
}

async function main() {
  const options = args(process.argv.slice(2));
  const reportBytes = await readFile(path.resolve(options.report));
  const report = JSON.parse(reportBytes.toString("utf8")); await validateRegressionReport(report);
  const issuedAt = new Date().toISOString(); const expiresAt = instant(options["expires-at"], "expires-at");
  if (expiresAt <= Date.now() || expiresAt > Date.now() + 24 * 60 * 60 * 1000) throw new Error("expires-at must be within the next 24 hours");
  const payload = {
    schemaVersion: 1, kind: report.kind, runId: bounded(options["run-id"], "runId"), issuedAt,
    expiresAt: new Date(expiresAt).toISOString(), reportSha256: sha256(reportBytes), artifactSha256: report.artifactSha256,
    suiteId: report.suite.id, suiteSha256: report.suite.sha256, runnerId: report.runner.id,
    runnerExecutableSha256: report.runner.executableSha256, environmentSha256: report.runner.environmentSha256,
  };
  const payloadBytes = canonical(payload);
  const privateKey = createPrivateKey({ key: await readFile(path.resolve(options["private-key"])), passphrase: process.env.REA_REGRESSION_WORKER_PASSPHRASE });
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("regression worker private key must be Ed25519");
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const envelope = { format: REGRESSION_ATTESTATION_FORMAT, keyId: sha256(publicDer), payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${REGRESSION_ATTESTATION_FORMAT}\0`), payloadBytes]), privateKey).toString("base64") };
  const handle = await open(path.resolve(options.out), "wx", 0o644);
  try { await handle.writeFile(`${JSON.stringify(envelope, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: "signed", kind: report.kind, reportSha256: payload.reportSha256, artifactSha256: payload.artifactSha256, keyId: envelope.keyId, out: path.resolve(options.out) }, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => {
  process.stderr.write(`regression attestation error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
