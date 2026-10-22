import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, ".."); const cli = path.join(root, "scripts", "probe-cross-build-alignment.mjs");
const digestBytes = (value) => createHash("sha256").update(value).digest();

async function fixture(stable) {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-cross-build-")); const variants = [];
  const common = Buffer.concat([digestBytes("common-a"), digestBytes("common-b"), digestBytes("common-c")]);
  for (let index = 0; index < 20; index += 1) {
    const unique = Buffer.concat([digestBytes(`variant-${index}-a`), digestBytes(`variant-${index}-b`), digestBytes(`variant-${index}-c`), digestBytes(`variant-${index}-d`)]);
    const bytes = stable ? Buffer.concat([common, unique]) : unique; const file = path.join(directory, `variant-${index}.bin`); const attestation = path.join(directory, `variant-${index}.attestation.json`); await writeFile(file, bytes); await writeFile(attestation, JSON.stringify({ fixture: index })); variants.push({ path: path.basename(file), attestation: path.basename(attestation) });
  }
  const manifest = path.join(directory, "manifest.json"); const report = path.join(directory, "report.json"); await writeFile(manifest, JSON.stringify({ schemaVersion: 1, variants }));
  return { directory, artifact: path.join(directory, variants[0].path), manifest, report };
}

test("does not report alignment across twenty independently diversified regions", async () => {
  const value = await fixture(false); const result = spawnSync(process.execPath, [cli, "--artifact", value.artifact, "--manifest", value.manifest, "--report", value.report], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr); const report = JSON.parse(await readFile(value.report, "utf8")); assert.equal(report.status, "not-recovered"); assert.equal(report.coverage.observedVariants, 20); assert.equal(report.analysis.stableWindows, 0);
});

test("recovers a stable protected region shared across diversified builds", async () => {
  const value = await fixture(true); const result = spawnSync(process.execPath, [cli, "--artifact", value.artifact, "--manifest", value.manifest, "--report", value.report], { encoding: "utf8" });
  assert.equal(result.status, 2, result.stderr); const report = JSON.parse(await readFile(value.report, "utf8")); assert.equal(report.status, "recovered"); assert.ok(report.analysis.stableByteRatio > report.thresholds.maximumStableByteRatio); assert.match(report.analysis.stableWindowSetSha256, /^[a-f0-9]{64}$/);
});

test("rejects duplicate builds and undersized corpora instead of inflating support", async () => {
  const value = await fixture(false); const manifest = JSON.parse(await readFile(value.manifest, "utf8")); manifest.variants[1].path = manifest.variants[0].path; await writeFile(value.manifest, JSON.stringify(manifest));
  let result = spawnSync(process.execPath, [cli, "--artifact", value.artifact, "--manifest", value.manifest, "--report", value.report], { encoding: "utf8" }); assert.equal(result.status, 1); assert.match(result.stderr, /duplicate path/);
  manifest.variants = manifest.variants.slice(0, 19); await writeFile(value.manifest, JSON.stringify(manifest)); result = spawnSync(process.execPath, [cli, "--artifact", value.artifact, "--manifest", value.manifest, "--report", value.report], { encoding: "utf8" }); assert.equal(result.status, 1); assert.match(result.stderr, /requires 20\.\.64/);
});
