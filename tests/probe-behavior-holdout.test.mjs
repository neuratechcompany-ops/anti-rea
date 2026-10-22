import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const probe = path.resolve(import.meta.dirname, "..", "scripts", "probe-behavior-holdout.mjs");
const runner = `let s="";process.stdin.on("data",c=>s+=c).on("end",()=>{const v=JSON.parse(s);process.stdout.write(JSON.stringify(globalThis.run(v)))})\n`;
async function fixture(candidateBody) {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-holdout-")); const artifact = path.join(directory, "release.js"), reference = path.join(directory, "reference.mjs"), candidate = path.join(directory, "candidate.mjs"), corpus = path.join(directory, "corpus.json"), report = path.join(directory, "report.json");
  await writeFile(artifact, "export const release=true;\n");
  await writeFile(reference, `globalThis.run=v=>({allowed:v.vip&&v.total>100,price:v.vip&&v.total>100?v.total*0.8:v.total});${runner}`);
  await writeFile(candidate, `${candidateBody}${runner}`);
  await writeFile(corpus, `${JSON.stringify([{ total: 50, vip: false }, { total: 200, vip: true }, { total: 200, vip: false }])}\n`);
  return { directory, artifact, reference, candidate, corpus, report };
}
function invoke(value, timeout = "2000") { return spawnSync(process.execPath, [probe, "--artifact", value.artifact, "--reference", value.reference, "--candidate", value.candidate, "--corpus", value.corpus, "--timeout-ms", timeout, "--report", value.report], { encoding: "utf8", timeout: 10000 }); }

test("recovers equivalent behavior despite different candidate source structure", async () => {
  const value = await fixture("globalThis.run=x=>{let p=x.total;if(x.vip){if(p>100)p-=p/5}return {price:p,allowed:Boolean(x.vip&&x.total>100)}};");
  const result = invoke(value); assert.equal(result.status, 2, result.stderr); const report = JSON.parse(await readFile(value.report, "utf8"));
  assert.equal(report.status, "recovered"); assert.equal(report.coverage.complete, true); assert.deepEqual(report.reference.behavior, report.candidate.behavior); assert.equal(report.corpus.inputSha256.length, 3); assert.equal(JSON.stringify(report).includes('"total":200'), false);
});

test("does not claim recovery when holdout behavior differs", async () => {
  const value = await fixture("globalThis.run=x=>({allowed:false,price:x.total});"); const result = invoke(value); assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(await readFile(value.report, "utf8")); assert.equal(report.status, "not-recovered"); assert.equal(report.coverage.complete, true); assert.notDeepEqual(report.reference.behavior, report.candidate.behavior);
});

test("fails closed when the recovered candidate times out", async () => {
  const value = await fixture("globalThis.run=x=>{while(true){} };"); const result = invoke(value, "100"); assert.equal(result.status, 1);
  const report = JSON.parse(await readFile(value.report, "utf8")); assert.equal(report.status, "invalid"); assert.equal(report.coverage.complete, false); assert.match(report.executionError, /timeout/);
});

test("fails closed when a candidate mutates its executable during the oracle run", async () => {
  const value = await fixture('import {appendFileSync} from "node:fs";appendFileSync(new URL(import.meta.url),"\\n");globalThis.run=x=>({allowed:x.vip&&x.total>100,price:x.vip&&x.total>100?x.total*0.8:x.total});');
  const result = invoke(value); assert.equal(result.status, 1); const report = JSON.parse(await readFile(value.report, "utf8"));
  assert.equal(report.status, "invalid"); assert.match(report.executionError, /candidate changed during holdout execution/);
});
