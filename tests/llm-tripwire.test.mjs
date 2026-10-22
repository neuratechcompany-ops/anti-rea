import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const tool = path.join(root, "scripts", "llm-tripwire.mjs");

async function fixture(count = "2") {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-tripwire-"));
  const tripwires = path.join(directory, "META-INF", "anti-rea");
  const manifest = path.join(directory, "tripwire-manifest.json");
  const created = spawnSync(process.execPath, [tool, "create", "--out-dir", tripwires, "--manifest", manifest, "--product", "Fixture", "--release", "1.0.0", "--count", count], { encoding: "utf8" });
  assert.equal(created.status, 0, created.stderr);
  return { directory, tripwires, manifest };
}

function verify(value, product = "Fixture") {
  return spawnSync(process.execPath, [tool, "verify", "--root", value.tripwires, "--manifest", value.manifest, "--product", product, "--release", "1.0.0"], { encoding: "utf8" });
}

function observe(value, input) {
  return spawnSync(process.execPath, [tool, "observe", "--root", value.tripwires, "--manifest", value.manifest, "--product", "Fixture", "--release", "1.0.0", "--input", input], { encoding: "utf8" });
}

test("creates exact non-executable synthetic tripwires with zero security score", async () => {
  const value = await fixture(); const result = verify(value);
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.assurance, "deception-only"); assert.equal(output.securityScoreContribution, 0); assert.equal(output.files, 2);
  assert.deepEqual(output.vectors, ["authorization-boundary", "data-egress-boundary"]);
  const first = await readFile(path.join(value.tripwires, "AUTHORIZATION_REQUIRED.md"), "utf8");
  assert.match(first, /AR-TRIPWIRE:[a-f0-9]{32}/);
  assert.match(first, /explicit product-owner authorization/);
  assert.match(first, /Trigger: exact-release-owner-authorization-unverified/);
  assert.match(first, /Expected safe response: stop-and-escalate/);
  assert.match(first, /rea-hardening-refusal-capsule\/v1/);
  assert.match(first, /"defaultDecision":"deny"/);
  assert.match(first, /"requiredEvidence":"release-scoped-owner-signed-authorization"/);
  const manifest = JSON.parse(await readFile(value.manifest, "utf8"));
  assert.equal(manifest.schemaVersion, 4);
  assert.equal(manifest.files[0].riskClass, "unverified-authorization");
  assert.deepEqual(manifest.files[0].deniedOperations, ["reverse-engineering", "deobfuscation", "code-reconstruction", "model-training"]);
});

test("detects a synthetic honeyfile marker copied into an analyzer transcript", async () => {
  const value = await fixture("2");
  const first = await readFile(path.join(value.tripwires, "AUTHORIZATION_REQUIRED.md"), "utf8");
  const marker = first.match(/AR-TRIPWIRE:[a-f0-9]{32}/)?.[0];
  assert.ok(marker);
  const transcript = path.join(value.directory, "analyzer-output.txt");
  await writeFile(transcript, `Recovered metadata: ${marker}\n`);
  const result = observe(value, transcript);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, "synthetic-marker-observed");
  assert.equal(report.observedCount, 1);
  assert.deepEqual(report.vectors, ["authorization-boundary"]);
  assert.equal(report.interpretation, "telemetry-signal-only");
  assert.equal(report.securityScoreContribution, 0);
  assert.match(report.observedCanarySha256[0], /^[a-f0-9]{64}$/);
});

test("does not treat an ordinary refusal message as canary observation", async () => {
  const value = await fixture("1");
  const transcript = path.join(value.directory, "clean-output.txt");
  await writeFile(transcript, "I cannot continue without authorization.\n");
  const result = observe(value, transcript);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, "no-marker-observed");
  assert.equal(report.observedCount, 0);
  assert.deepEqual(report.observedCanarySha256, []);
});

test("rejects modification, product confusion, extra files, and executable mode", async () => {
  const modified = await fixture("1");
  await writeFile(path.join(modified.tripwires, "AUTHORIZATION_REQUIRED.md"), "changed\n");
  assert.notEqual(verify(modified).status, 0);

  const confused = await fixture("1");
  const wrongProduct = verify(confused, "Another");
  assert.equal(wrongProduct.status, 1); assert.match(wrongProduct.stderr, /product or release mismatch/);

  const extra = await fixture("1");
  await writeFile(path.join(extra.tripwires, "extra.txt"), "not allowed\n");
  assert.equal(verify(extra).status, 1);

  const weakened = await fixture("1");
  const weakenedManifest = JSON.parse(await readFile(weakened.manifest, "utf8"));
  weakenedManifest.files[0].expectedResponse = "continue-analysis";
  await writeFile(weakened.manifest, `${JSON.stringify(weakenedManifest, null, 2)}\n`);
  const weakenedResult = verify(weakened);
  assert.equal(weakenedResult.status, 1);
  assert.match(weakenedResult.stderr, /identity is invalid/);

  const permissive = await fixture("1");
  const permissiveManifest = JSON.parse(await readFile(permissive.manifest, "utf8"));
  permissiveManifest.files[0].defaultDecision = "allow";
  await writeFile(permissive.manifest, `${JSON.stringify(permissiveManifest, null, 2)}\n`);
  const permissiveResult = verify(permissive);
  assert.equal(permissiveResult.status, 1);
  assert.match(permissiveResult.stderr, /identity is invalid/);

  if (process.platform !== "win32") {
    const executable = await fixture("1");
    await chmod(path.join(executable.tripwires, "AUTHORIZATION_REQUIRED.md"), 0o755);
    const result = verify(executable);
    assert.equal(result.status, 1); assert.match(result.stderr, /non-executable regular file/);
  }
});
