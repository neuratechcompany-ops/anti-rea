import assert from "node:assert/strict";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { analyzeCrossBuildSemantic } from "../scripts/probe-cross-build-semantic.mjs";

function graph(index, diverse = false) {
  const count = diverse ? 5 + index : 7; const ids = Array.from({ length: count }, (_, node) => `variant-${index}-node-${node}`); const ops = ["input", "load", "arithmetic", "compare", "convert", "table", "crypto", "store"];
  return {
    schemaVersion: 1, entry: ids[0],
    nodes: ids.map((id, node) => ({ id, op: node === 0 ? "input" : node === count - 1 ? "return" : ops[(diverse ? node + index : node) % ops.length], valueClass: node === count - 1 ? "int" : "int" })),
    controlEdges: ids.slice(0, -1).map((id, node) => ({ from: id, to: ids[node + 1], kind: node === count - 2 ? "return" : "fallthrough" })),
    dataEdges: ids.slice(0, -1).map((id, node) => ({ from: id, to: ids[node + 1], input: 0 })),
  };
}

async function fixture(diverse) {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-semantic-cross-build-")); const extractor = path.join(directory, "extractor.mjs");
  await writeFile(extractor, '#!/usr/bin/env node\nimport { readFileSync } from "node:fs"; process.stdout.write(readFileSync(process.argv[2]));\n'); await chmod(extractor, 0o755);
  const adapter = path.join(directory, "adapter.json"); await writeFile(adapter, JSON.stringify({ schemaVersion: 1, id: "fixture-semantic-ir", family: "semantic-ir", type: "probe", surfaces: ["native"], command: extractor, args: ["{artifact}"], timeoutMs: 5000, maxOutputBytes: 1024 * 1024, outputFormat: "json", requireNonEmpty: true }));
  const variants = [];
  for (let index = 0; index < 20; index += 1) { const region = path.join(directory, `region-${index}.json`); const attestation = path.join(directory, `attestation-${index}.json`); await writeFile(region, JSON.stringify(graph(index, diverse))); await writeFile(attestation, JSON.stringify({ index })); variants.push({ path: region, attestation }); }
  return { adapter, directory, extractor, variants };
}

test("semantic cross-build probe recovers renamed and reordered equivalent IR", async () => {
  const value = await fixture(false); const report = await analyzeCrossBuildSemantic(value.variants[0].path, value.variants, value.adapter);
  assert.equal(report.status, "recovered"); assert.equal(report.analysis.alignedVariants, 20); assert.equal(report.analysis.maximumPairwiseFeatureJaccard, 1); assert.equal(report.coverage.complete, true);
});

test("semantic cross-build probe does not align structurally diversified IR", async () => {
  const value = await fixture(true); const report = await analyzeCrossBuildSemantic(value.variants[0].path, value.variants, value.adapter);
  assert.equal(report.status, "not-recovered"); assert.equal(report.analysis.alignedVariants, 1); assert.ok(report.analysis.maximumPairwiseFeatureJaccard <= 0.7);
});

test("semantic cross-build probe rejects duplicate bytes and incomplete corpora", async () => {
  const value = await fixture(false); await assert.rejects(() => analyzeCrossBuildSemantic(value.variants[0].path, value.variants.slice(0, 19), value.adapter), /20\.\.64/);
  await writeFile(value.variants[1].path, await import("node:fs/promises").then(({ readFile }) => readFile(value.variants[0].path)));
  await assert.rejects(() => analyzeCrossBuildSemantic(value.variants[0].path, value.variants, value.adapter), /duplicate bytes/);
});

test("semantic cross-build probe detects a later extractor mutating an earlier variant", async () => {
  const value = await fixture(true);
  await writeFile(value.extractor, `#!/usr/bin/env node
import { appendFileSync, readFileSync } from "node:fs"; import path from "node:path";
const target=process.argv[2]; if(path.basename(target)==="region-1.json") appendFileSync(path.join(path.dirname(target),"region-0.json")," "); process.stdout.write(readFileSync(target));
`); await chmod(value.extractor, 0o755);
  await assert.rejects(() => analyzeCrossBuildSemantic(value.variants[0].path, value.variants, value.adapter), /changed after extraction/);
});
