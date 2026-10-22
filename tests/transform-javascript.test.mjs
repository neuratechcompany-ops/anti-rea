import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const transformer = path.join(root, "scripts", "transform-javascript.mjs");
const input = path.join(root, "tests", "fixtures", "javascript-owned-bundle.js");
const canaries = path.join(root, "tests", "fixtures", "javascript-canaries.json");

async function transform(profileName, seed = "424242") {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-js-transform-"));
  const output = path.join(directory, "protected.js");
  const report = path.join(directory, "report.json");
  const profile = path.join(root, "profiles", `${profileName}.json`);
  const result = spawnSync(process.execPath, [transformer, "--input", input, "--output", output, "--profile", profile, "--report", report, "--seed", seed, "--canaries", canaries], { encoding: "utf8", timeout: 30000 });
  return { directory, output, report, result };
}

test("balanced and strong profiles hide declared static facts and preserve behavior", async () => {
  const baseline = spawnSync(process.execPath, [input], { encoding: "utf8" });
  assert.equal(baseline.status, 0);
  for (const profile of ["javascript-balanced", "javascript-strong"]) {
    const current = await transform(profile);
    assert.equal(current.result.status, 0, `${profile}: ${current.result.stderr}`);
    const protectedRun = spawnSync(process.execPath, [current.output], { encoding: "utf8", timeout: 10000 });
    assert.equal(protectedRun.status, 0, `${profile}: ${protectedRun.stderr}`);
    assert.equal(protectedRun.stdout, baseline.stdout);
    const outputText = await readFile(current.output, "utf8");
    const values = JSON.parse(await readFile(canaries, "utf8"));
    for (const value of values) assert.ok(!outputText.includes(value), `${profile} leaked ${value}`);
    const report = JSON.parse(await readFile(current.report, "utf8"));
    assert.equal(report.canaries.plaintextRecovered, 0);
    assert.equal(report.transformer.version, "5.9.0");
  }
});

test("the same profile and seed produce identical artifacts", async () => {
  const first = await transform("javascript-balanced", "7");
  const second = await transform("javascript-balanced", "7");
  assert.equal(first.result.status, 0, first.result.stderr);
  assert.equal(second.result.status, 0, second.result.stderr);
  assert.deepEqual(await readFile(first.output), await readFile(second.output));
});
