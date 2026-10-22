import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const verifier = path.join(root, "scripts", "verify-web-artifact.mjs");

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-hardening-test-"));
  const artifact = path.join(directory, "dist");
  await mkdir(artifact);
  return { directory, artifact, report: path.join(directory, "report.json") };
}

function run(args) {
  return spawnSync(process.execPath, [verifier, ...args], { encoding: "utf8" });
}

test("passes a minimal artifact and inventories hosts", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "app.js"), "fetch('https://api.example.test/v1/items')");
  const result = run(["--artifact", current.artifact, "--report", current.report]);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(await readFile(current.report, "utf8"));
  assert.equal(report.status, "passed");
  assert.equal(report.assurance.level, "bounded-static");
  assert.ok(report.assurance.limitations.length >= 1);
  assert.match(report.artifactSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(report.endpoints.map((item) => item.host), ["api.example.test"]);
});

test("fails closed on source maps and redacts credential-like literals", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "app.js"), "const api_key = 'abcdefghijklmnopqrstuvwxyz123456';\n//# sourceMappingURL=app.js.map");
  await writeFile(path.join(current.artifact, "app.js.map"), JSON.stringify({ sourcesContent: ["secret source"] }));
  const result = run(["--artifact", current.artifact, "--report", current.report]);
  assert.equal(result.status, 2, result.stderr);
  const reportText = await readFile(current.report, "utf8");
  const report = JSON.parse(reportText);
  assert.equal(report.status, "failed");
  assert.ok(report.findings.some((finding) => finding.rule === "credential-assignment"));
  assert.ok(report.findings.some((finding) => finding.rule === "source-map-file"));
  assert.ok(!reportText.includes("abcdefghijklmnopqrstuvwxyz123456"));
});

test("enforces an explicit external-host allowlist", async () => {
  const current = await fixture();
  const policy = path.join(current.directory, "policy.json");
  await writeFile(path.join(current.artifact, "app.js"), "fetch('https://unexpected.example/v1')");
  await writeFile(policy, JSON.stringify({ version: 1, allowedHosts: ["api.example.test"] }));
  const result = run(["--artifact", current.artifact, "--policy", policy, "--report", current.report]);
  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(await readFile(current.report, "utf8"));
  assert.ok(report.findings.some((finding) => finding.rule === "unapproved-external-host"));
});

test("treats an empty explicit allowlist as no external hosts allowed", async () => {
  const current = await fixture();
  const policy = path.join(current.directory, "policy.json");
  await writeFile(path.join(current.artifact, "app.js"), "fetch('https://unexpected.example/v1')");
  await writeFile(policy, JSON.stringify({ version: 1, allowedHosts: [] }));
  const result = run(["--artifact", current.artifact, "--policy", policy, "--report", current.report]);
  assert.equal(result.status, 2, result.stderr);
});

test("refuses to write the report inside the artifact", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "app.js"), "console.log('ok')");
  const result = run(["--artifact", current.artifact, "--report", path.join(current.artifact, "report.json")]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /outside the artifact directory/);
});

test("fails when an expected host is hidden by arbitrary computation", async () => {
  const current = await fixture();
  const policy = path.join(current.directory, "policy.json");
  const host = "computed.example";
  const encoded = [...`https://${host}/v1`].map((character) => character.charCodeAt(0) ^ 23);
  await writeFile(path.join(current.artifact, "app.js"), `fetch([${encoded}].map(n => String.fromCharCode(n ^ 23)).join(''))`);
  await writeFile(policy, JSON.stringify({ version: 1, allowedHosts: [host], requiredHosts: [host] }));
  const result = run(["--artifact", current.artifact, "--policy", policy, "--report", current.report]);
  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(await readFile(current.report, "utf8"));
  assert.ok(report.findings.some((finding) => finding.rule === "required-host-not-observed"));
});

test("rejects duplicate policy fields", async () => {
  const current = await fixture();
  const policy = path.join(current.directory, "policy.json");
  await writeFile(path.join(current.artifact, "app.js"), "console.log('ok')");
  await writeFile(policy, '{"version":1,"allowedHosts":[],"allowedHosts":["bypass.example"]}');
  const result = run(["--artifact", current.artifact, "--policy", policy, "--report", current.report]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /duplicate policy field/);
});

test("enforces an exact release file inventory", async () => {
  const current = await fixture();
  const policy = path.join(current.directory, "policy.json");
  await writeFile(path.join(current.artifact, "app.js"), "console.log('ok')");
  await writeFile(path.join(current.artifact, "forgotten.txt"), "debug artifact");
  await writeFile(policy, JSON.stringify({ version: 1, allowedFiles: ["app.js", "missing.css"] }));
  const result = run(["--artifact", current.artifact, "--policy", policy, "--report", current.report]);
  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(await readFile(current.report, "utf8"));
  assert.ok(report.findings.some((finding) => finding.rule === "required-file-missing"));
  assert.ok(report.findings.some((finding) => finding.rule === "unexpected-release-file"));
});
