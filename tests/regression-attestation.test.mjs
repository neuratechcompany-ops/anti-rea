import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { verifyRegressionAttestation } from "../scripts/regression-attestation.mjs";

const root = path.resolve(import.meta.dirname, "..");
const tool = path.join(root, "scripts", "regression-attestation.mjs");
const sha = (value) => createHash("sha256").update(value).digest("hex");

async function fixture(kind = "functional") {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-regression-"));
  const suite = path.join(directory, "suite.mjs"); const result = path.join(directory, "result.json"); const report = path.join(directory, "report.json");
  const suiteBytes = Buffer.from("export const test = true;\n"); const resultBytes = Buffer.from("{\"passed\":true}\n");
  await writeFile(suite, suiteBytes); await writeFile(result, resultBytes);
  const executable = process.execPath; const executableSha256 = sha(await readFile(executable)); const environmentSha256 = sha(Buffer.from("owned-runner-image"));
  const value = {
    format: "rea-hardening-regression-report/v1", schemaVersion: 1, kind, artifactSha256: "a".repeat(64),
    suite: { id: `${kind}-suite`, path: suite, sha256: sha(suiteBytes) },
    runner: { id: "owned-runner", executablePath: executable, executableSha256, environmentSha256 },
    startedAt: new Date(Date.now() - 2000).toISOString(), completedAt: new Date(Date.now() - 1000).toISOString(), status: "passed",
    result: { path: result, bytes: resultBytes.length, sha256: sha(resultBytes) },
    summary: kind === "performance" ? { metrics: [{ id: "startup-ms", unit: "ms", value: 10, maximum: 20 }] } : { total: 1, passed: 1, failed: 0, skipped: 0 },
  };
  await writeFile(report, `${JSON.stringify(value, null, 2)}\n`);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, "private.pem"); const publicPath = path.join(directory, "public.pem"); const attestation = path.join(directory, "attestation.json");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" })); await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }));
  return { directory, suite, result, report, value, privatePath, publicPath, attestation, executableSha256, environmentSha256 };
}

function signFixture(value) {
  return spawnSync(process.execPath, [tool, "sign", "--report", value.report, "--private-key", value.privatePath, "--run-id", "owned-run-1", "--expires-at", new Date(Date.now() + 60 * 60 * 1000).toISOString(), "--out", value.attestation], { encoding: "utf8" });
}

test("signs and verifies an exact typed regression report", async () => {
  const value = await fixture(); const signed = signFixture(value);
  assert.equal(signed.status, 0, signed.stderr);
  const verified = await verifyRegressionAttestation(await readFile(value.attestation), await readFile(value.report), await readFile(value.publicPath), {
    artifactSha256: "a".repeat(64), kind: "functional", suiteId: "functional-suite", suiteSha256: value.value.suite.sha256,
    runnerId: "owned-runner", runnerExecutableSha256: value.executableSha256, environmentSha256: value.environmentSha256,
  });
  assert.equal(verified.report.status, "passed");
});

test("rejects raw-result tampering and performance budget violations", async () => {
  const value = await fixture(); assert.equal(signFixture(value).status, 0);
  await writeFile(value.result, "{\"passed\":false}\n");
  await assert.rejects(async () => verifyRegressionAttestation(await readFile(value.attestation), await readFile(value.report), await readFile(value.publicPath), {
    artifactSha256: "a".repeat(64), kind: "functional", suiteId: "functional-suite", suiteSha256: value.value.suite.sha256,
    runnerId: "owned-runner", runnerExecutableSha256: value.executableSha256, environmentSha256: value.environmentSha256,
  }), /raw result no longer matches/);

  const performance = await fixture("performance"); performance.value.summary.metrics[0].value = 21;
  await writeFile(performance.report, `${JSON.stringify(performance.value)}\n`);
  const rejected = signFixture(performance);
  assert.equal(rejected.status, 1); assert.match(rejected.stderr, /exceeds its budget/);
});
