#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Exercise the real scanner with controlled synthetic strings. This catches a
// disabled rule set and overbroad fixture exemptions even when the repo is clean.
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const config = path.join(repository, ".gitleaks.toml");
const binary = process.argv[2] ?? "gitleaks";
const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-secret-control-"));
const token = ["ghp", "Ab9cD2eF4gH6iJ8kL0mN3pQ5rS7tU1vW9xY2"].join("_");
const fixture = ["sk-live", "9f8e7d6c5b4a39281706secret"].join("-");
const algorithm = ["chacha20", "poly1305"].join("-");
const tokenLine = `const token = "${token}";\n`;
const cases = [
  { file: "src/runtime.js", content: tokenLine, detected: true },
  { file: "tests/probe.test.mjs", content: tokenLine, detected: true },
  // Even an explicitly exempted file must still detect unrelated credentials.
  { file: "examples/secret.before.js", content: tokenLine, detected: true },
  { file: "examples/verification-before-after.md", content: `API_KEY = "${fixture}"\n`, detected: false },
  { file: "src/moved-fixture.js", content: `const API_KEY = "${fixture}";\n`, detected: true },
  // An allowlisted value must not exempt a longer credential that contains it.
  { file: "nested/examples/secret.before.js", content: `const API_KEY = "${fixture}X7a9";\n`, detected: true },
  { file: "tests/virtualize-javascript.test.mjs", content: `receipt.key.encryption, "${algorithm}"\n`, detected: false },
  { file: "src/moved-algorithm.js", content: `const API_KEY = "${algorithm}";\n`, detected: true },
  { file: "src/comment.js", content: `${tokenLine.trimEnd()} // gitleaks:allow\n`, detected: true },
  { file: "src/clean.js", content: 'const greeting = "hello";\n', detected: false },
];

try {
  for (const item of cases) {
    const filename = path.join(directory, item.file);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, item.content, { flag: "wx" });
  }
  const result = spawnSync(binary, [
    "dir", directory, "--config", config, "--redact", "--no-banner",
    "--ignore-gitleaks-allow", "--gitleaks-ignore-path", directory,
    "--report-format", "json", "--report-path", "-", "--log-level", "error",
  ], { encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024, cwd: directory });
  if (result.error) throw result.error;
  assert.equal(result.status, 1, "positive control must make Gitleaks exit 1; a clean result can mean scanning is disabled");
  const findings = JSON.parse(result.stdout);
  assert.ok(Array.isArray(findings) && findings.length > 0, "positive control must produce findings");
  const detected = new Set(findings.map((finding) => {
    assert.equal(finding.Secret, "REDACTED", "scanner output must redact synthetic secret values");
    assert.ok(typeof finding.RuleID === "string" && finding.RuleID.length > 0);
    return path.relative(directory, path.resolve(directory, finding.File)).split(path.sep).join("/");
  }));
  assert.deepEqual([...detected].sort(), cases.filter((item) => item.detected).map((item) => item.file).sort(), "scanner must detect controls without broad fixture or test-path exemptions");
  process.stdout.write(`Secret scanner controls passed: ${detected.size} detected, ${cases.length - detected.size} correctly allowed.\n`);
} finally {
  // Only the fresh, dedicated directory created above is removed.
  await rm(directory, { recursive: true, force: true });
}
