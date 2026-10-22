import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const runner = path.join(root, "scripts", "run-probe.mjs");
const fake = path.join(root, "tests", "fixtures", "fake-probe.mjs");

async function invoke(mode, overrides = {}, runnerEnv = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-probe-"));
  const artifact = path.join(directory, "artifact.bin");
  const adapter = path.join(directory, "adapter.json");
  const evidence = path.join(directory, "evidence");
  await writeFile(artifact, "fixture");
  await writeFile(adapter, JSON.stringify({
    schemaVersion: 1, id: "fake-probe", family: "fixture", type: "probe", surfaces: ["test"],
    command: process.execPath, args: [fake, mode, "{artifact}"], timeoutMs: 10000,
    maxOutputBytes: 1048576, outputFormat: "json", requireNonEmpty: true, ...overrides,
  }));
  const result = spawnSync(process.execPath, [runner, "--adapter", adapter, "--artifact", artifact, "--evidence", evidence], { encoding: "utf8", env: { ...process.env, ...runnerEnv } });
  return { result, evidence };
}

test("records a valid probe with hashed raw evidence", async () => {
  const { result, evidence } = await invoke("json");
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(await readFile(path.join(evidence, "probe.json"), "utf8"));
  assert.equal(report.status, "valid");
  assert.equal(report.adapter.family, "fixture");
  assert.match(report.invocation.executable.sha256, /^[a-f0-9]{64}$/);
  assert.match(report.evidence.stdout.sha256, /^[a-f0-9]{64}$/);
  assert.ok(report.evidence.stdout.bytes > 0);
});

test("does not expose parent secrets to an untrusted analyzer", async () => {
  const { result, evidence } = await invoke("env", {}, { ANTI_REA_SENTINEL_SECRET: "must-not-reach-probe" });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(await readFile(path.join(evidence, "stdout.bin"), "utf8"));
  assert.equal(report.leaked, false);
});

test("classifies empty and malformed analyzer output as invalid", async () => {
  for (const mode of ["empty", "bad-json", "failure"]) {
    const { result } = await invoke(mode);
    assert.equal(result.status, 2, `${mode}: ${result.stderr}`);
    assert.equal(JSON.parse(result.stdout).status, "invalid");
  }
});

test("terminates a probe that exceeds its evidence output limit", async () => {
  const { result } = await invoke("large", { maxOutputBytes: 1024, outputFormat: "text" });
  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.execution.outputLimitExceeded, true);
  assert.match(report.reasons.join(" "), /output byte limit/);
});

test("classifies a missing analyzer executable as blocked", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-probe-blocked-"));
  const artifact = path.join(directory, "artifact.bin");
  const adapter = path.join(directory, "adapter.json");
  const evidence = path.join(directory, "evidence");
  await writeFile(artifact, "fixture");
  await writeFile(adapter, JSON.stringify({
    schemaVersion: 1, id: "missing-probe", family: "fixture", type: "probe", surfaces: ["test"],
    executableEnv: "DEFINITELY_MISSING_REA_TEST_CLI", args: ["{artifact}"], timeoutMs: 10000,
    maxOutputBytes: 1048576, outputFormat: "text", requireNonEmpty: true,
  }));
  const result = spawnSync(process.execPath, [runner, "--adapter", adapter, "--artifact", artifact, "--evidence", evidence], { encoding: "utf8" });
  assert.equal(result.status, 3, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, "blocked");
});

test("ships valid fail-closed WASM and native structural adapters", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-structural-adapters-")); const artifact = path.join(directory, "artifact.bin"); await writeFile(artifact, "fixture");
  for (const [name, environment] of [["wabt-wasm2wat.json", "WASM2WAT"], ["native-cfg-export.json", "ANTI_REA_NATIVE_CFG_EXPORTER"]]) {
    const evidence = path.join(directory, name); const env = { ...process.env }; delete env[environment];
    const result = spawnSync(process.execPath, [runner, "--adapter", path.join(root, "adapters", name), "--artifact", artifact, "--evidence", evidence], { encoding: "utf8", env });
    assert.equal(result.status, 3, result.stderr); const report = JSON.parse(result.stdout); assert.equal(report.status, "blocked"); assert.match(report.reasons.join(" "), /not configured/);
  }
});
