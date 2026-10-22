import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { brotliCompressSync, gzipSync } from "node:zlib";

const root = path.resolve(import.meta.dirname, "..");
const cli = path.join(root, "scripts", "delivery-graph.mjs");

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-delivery-"));
  const release = path.join(directory, "release"); const update = path.join(directory, "update");
  await mkdir(release); await mkdir(update);
  await writeFile(path.join(release, "app.js"), "console.log('protected')\n");
  await writeFile(path.join(update, "manifest.json"), "{}\n");
  const descriptor = path.join(directory, "descriptor.json"); const report = path.join(directory, "report.json");
  await writeFile(descriptor, JSON.stringify({ schemaVersion: 1, surfaces: [
    { id: "release-primary", kind: "release", audience: "customer", path: release },
    { id: "update-stable", kind: "update", audience: "customer", path: update },
  ] }));
  return { directory, release, update, descriptor, report };
}

test("walks every declared delivery surface and binds its tree", async () => {
  const value = await fixture();
  const result = spawnSync(process.execPath, [cli, "--descriptor", value.descriptor, "--report", value.report], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(await readFile(value.report, "utf8"));
  assert.equal(report.status, "PASS");
  assert.deepEqual(report.surfaces.map((item) => item.kind), ["release", "update"]);
  assert.match(report.surfaces[0].treeSha256, /^[a-f0-9]{64}$/);
});

test("fails closed on source maps, credentials, symlinks, and nested archives", async () => {
  const value = await fixture();
  await writeFile(path.join(value.release, "app.js.map"), "{}\n");
  await writeFile(path.join(value.update, "payload.zip"), "PK\u0003\u0004");
  await writeFile(path.join(value.update, ".env"), 'API_KEY="this-is-a-real-looking-secret"\n');
  const result = spawnSync(process.execPath, [cli, "--descriptor", value.descriptor, "--report", value.report], { encoding: "utf8" });
  assert.equal(result.status, 2, result.stderr);
  const rules = JSON.parse(await readFile(value.report, "utf8")).surfaces.flatMap((item) => item.findings.map((finding) => finding.rule));
  assert.ok(rules.includes("source-map-file"));
  assert.ok(rules.includes("uninspected-archive"));
  assert.ok(rules.includes("sensitive-file"));
});

test("rejects a descriptor that silently drops the update channel", async () => {
  const value = await fixture();
  await writeFile(value.descriptor, JSON.stringify({ schemaVersion: 1, surfaces: [{ id: "release-primary", kind: "release", audience: "customer", path: value.release }] }));
  const result = spawnSync(process.execPath, [cli, "--descriptor", value.descriptor, "--report", value.report], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /descriptor is invalid/);
});

test("opens gzip and Brotli content instead of accepting opaque compression", async () => {
  const value = await fixture();
  await writeFile(path.join(value.release, "hidden.js.br"), brotliCompressSync(Buffer.from('const token="this-is-a-hidden-credential";\n')));
  await writeFile(path.join(value.update, "hidden.js.gz"), gzipSync(Buffer.from("//# sourceMappingURL=app.js.map\n")));
  const result = spawnSync(process.execPath, [cli, "--descriptor", value.descriptor, "--report", value.report], { encoding: "utf8" });
  assert.equal(result.status, 2, result.stderr);
  const rules = JSON.parse(await readFile(value.report, "utf8")).surfaces.flatMap((item) => item.findings.map((finding) => finding.rule));
  assert.ok(rules.includes("credential-assignment")); assert.ok(rules.includes("embedded-source-reference"));
});

test("rejects two named channels that resolve to the same tree", async () => {
  const value = await fixture();
  await writeFile(value.descriptor, JSON.stringify({ schemaVersion: 1, surfaces: [
    { id: "release-primary", kind: "release", audience: "customer", path: value.release },
    { id: "update-stable", kind: "update", audience: "customer", path: `${value.release}/../release` },
  ] }));
  const result = spawnSync(process.execPath, [cli, "--descriptor", value.descriptor, "--report", value.report], { encoding: "utf8" });
  assert.equal(result.status, 1); assert.match(result.stderr, /aliases another surface/);
});
