import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const transform = path.join(root, "scripts", "transform-javascript.mjs");
const compile = path.join(root, "scripts", "compile-node-bytecode.mjs");
const input = path.join(root, "tests", "fixtures", "javascript-owned-bundle.js");
const canaries = path.join(root, "tests", "fixtures", "javascript-canaries.json");
const profile = path.join(root, "profiles", "javascript-balanced.json");

test("compiles transformed code to executable V8 bytecode without plaintext canaries", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-bytecode-"));
  const protectedJs = path.join(directory, "protected.js");
  const transformReport = path.join(directory, "transform.json");
  const bytecode = path.join(directory, "protected.jsc");
  const loader = path.join(directory, "protected.cjs");
  const bytecodeReport = path.join(directory, "bytecode.json");
  const transformed = spawnSync(process.execPath, [transform, "--input", input, "--output", protectedJs, "--profile", profile, "--report", transformReport, "--seed", "9090", "--canaries", canaries], { encoding: "utf8", timeout: 30000 });
  assert.equal(transformed.status, 0, transformed.stderr);
  const compiled = spawnSync(process.execPath, [compile, "--input", protectedJs, "--transform-report", transformReport, "--bytecode", bytecode, "--loader", loader, "--report", bytecodeReport, "--canaries", canaries], { encoding: "utf8", timeout: 30000 });
  assert.equal(compiled.status, 0, compiled.stderr);

  const baselineRun = spawnSync(process.execPath, [input], { encoding: "utf8" });
  const bytecodeRun = spawnSync(process.execPath, [loader], {
    encoding: "utf8",
    timeout: 10000,
    env: { ...process.env, NODE_PATH: path.join(root, "node_modules") },
  });
  assert.equal(bytecodeRun.status, 0, bytecodeRun.stderr);
  assert.equal(bytecodeRun.stdout, baselineRun.stdout);
  const bytes = await readFile(bytecode);
  for (const value of JSON.parse(await readFile(canaries, "utf8"))) assert.ok(!bytes.includes(Buffer.from(value)), `bytecode leaked ${value}`);
  const report = JSON.parse(await readFile(bytecodeReport, "utf8"));
  assert.equal(report.canaries.plaintextRecovered, 0);
  assert.equal(report.runtimeBinding.node, process.versions.node);
});

test("rejects a transform profile that is incompatible with bytecode", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-bytecode-incompatible-"));
  const protectedJs = path.join(directory, "protected.js");
  const transformReport = path.join(directory, "transform.json");
  const strongProfile = path.join(root, "profiles", "javascript-strong.json");
  const transformed = spawnSync(process.execPath, [transform, "--input", input, "--output", protectedJs, "--profile", strongProfile, "--report", transformReport, "--seed", "19", "--canaries", canaries], { encoding: "utf8", timeout: 30000 });
  assert.equal(transformed.status, 0, transformed.stderr);
  const result = spawnSync(process.execPath, [compile, "--input", protectedJs, "--transform-report", transformReport, "--bytecode", path.join(directory, "out.jsc"), "--loader", path.join(directory, "out.cjs"), "--report", path.join(directory, "bytecode.json")], { encoding: "utf8", timeout: 30000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /not compatible with node-bytecode/);
});
