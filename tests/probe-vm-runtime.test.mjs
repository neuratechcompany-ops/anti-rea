import assert from "node:assert/strict";
import { createCipheriv, randomBytes } from "node:crypto";
import { appendFile, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const virtualizer = path.join(root, "scripts", "virtualize-javascript.mjs");
const probe = path.join(root, "scripts", "probe-vm-runtime.mjs");
const input = path.join(root, "tests", "fixtures", "javascript-vm-owned.js");
const canaries = path.join(root, "tests", "fixtures", "javascript-vm-canaries.json");

test("framework-specific runtime hook recovers current VM payload and blocks a T2 claim", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-hook-"));
  const output = path.join(directory, "virtualized.js");
  const transformReport = path.join(directory, "virtualization.json");
  const transformed = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", output, "--report", transformReport, "--seed", "8080", "--canaries", canaries], { encoding: "utf8" });
  assert.equal(transformed.status, 0, transformed.stderr);
  const reportPath = path.join(directory, "probe.json");
  const result = spawnSync(process.execPath, [probe, "--artifact", output, "--canaries", canaries, "--virtualization-report", transformReport, "--report", reportPath], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(report.status, "recovered");
  assert.equal(report.canaries.recovered, 3);
  assert.ok(report.decodedPrograms >= 1);
  assert.equal(report.coverage.complete, true);
  assert.deepEqual(report.coverage.observedFunctionIds, report.coverage.expectedFunctionIds);
});

test("runtime hook still recovers an external-key VM after legitimate key provisioning", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-hook-external-"));
  const output = path.join(directory, "virtualized.js");
  const transformReport = path.join(directory, "virtualization.json");
  const key = "02".repeat(32);
  const transformed = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", output, "--report", transformReport, "--seed", "9090", "--canaries", canaries, "--key-mode", "external", "--key-slot", "__ANTI_REA_RUNTIME_KEY__", "--key-env", "ANTI_REA_TEST_BUILD_KEY"], { encoding: "utf8", env: { ...process.env, ANTI_REA_TEST_BUILD_KEY: key } });
  assert.equal(transformed.status, 0, transformed.stderr);
  const reportPath = path.join(directory, "probe.json");
  const result = spawnSync(process.execPath, [probe, "--artifact", output, "--canaries", canaries, "--virtualization-report", transformReport, "--report", reportPath, "--key-slot", "__ANTI_REA_RUNTIME_KEY__", "--key-env", "ANTI_REA_TEST_KEY"], { encoding: "utf8", timeout: 10000, env: { ...process.env, ANTI_REA_TEST_KEY: key } });
  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(report.status, "recovered");
  assert.equal(report.canaries.recovered, 3);
  assert.equal(report.coverage.complete, true);
});

test("runtime hook marks a partial protected-function execution invalid", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-hook-coverage-")); const output = path.join(directory, "virtualized.js"); const transformReport = path.join(directory, "virtualization.json");
  const transformed = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", output, "--report", transformReport, "--seed", "8181", "--canaries", canaries], { encoding: "utf8" }); assert.equal(transformed.status, 0, transformed.stderr);
  const receipt = JSON.parse(await readFile(transformReport, "utf8")); receipt.functions.push({ ...receipt.functions[0], id: "f".repeat(64), name: "unexecuted" }); await writeFile(transformReport, JSON.stringify(receipt));
  const reportPath = path.join(directory, "probe.json"); const result = spawnSync(process.execPath, [probe, "--artifact", output, "--canaries", canaries, "--virtualization-report", transformReport, "--report", reportPath], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 1); const report = JSON.parse(await readFile(reportPath, "utf8")); assert.equal(report.status, "invalid"); assert.equal(report.coverage.complete, false); assert.match(report.executionError, /incomplete protected function coverage/);
});

test("runtime hook observes plaintext across buffer, file, crypto, network, clone, IPC, base64, output, and WASM boundaries", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-boundaries-"));
  const output = path.join(directory, "virtualized.mjs"); const transformReport = path.join(directory, "virtualization.json");
  const transformed = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", output, "--report", transformReport, "--seed", "8282", "--canaries", canaries], { encoding: "utf8" }); assert.equal(transformed.status, 0, transformed.stderr);
  const secrets = {
    buffer: "BOUNDARY_BUFFER_SECRET", file: "BOUNDARY_FILE_SECRET", crypto: "BOUNDARY_CRYPTO_SECRET", network: "BOUNDARY_NETWORK_SECRET",
    clone: "BOUNDARY_CLONE_SECRET", ipc: "BOUNDARY_IPC_SECRET", base64: "BOUNDARY_BASE64_SECRET", output: "BOUNDARY_OUTPUT_SECRET",
  };
  const secretFile = path.join(directory, "runtime-secret.bin"); await writeFile(secretFile, secrets.file);
  const key = randomBytes(32); const iv = randomBytes(16); const cipher = createCipheriv("aes-256-ctr", key, iv); const encrypted = Buffer.concat([cipher.update(secrets.crypto), cipher.final()]);
  const points = (value) => [...value].map((character) => character.codePointAt(0));
  await appendFile(output, `\n{\n` +
    `  Buffer.from(${JSON.stringify(Buffer.from(secrets.buffer).toString("base64"))}, "base64").toString("utf8");\n` +
    `  const fsBoundary = await import("node:fs"); fsBoundary.readFileSync(${JSON.stringify(secretFile)});\n` +
    `  const cryptoBoundary = await import("node:crypto"); const decipher = cryptoBoundary.createDecipheriv("aes-256-ctr", Buffer.from(${JSON.stringify(key.toString("hex"))}, "hex"), Buffer.from(${JSON.stringify(iv.toString("hex"))}, "hex")); Buffer.concat([decipher.update(Buffer.from(${JSON.stringify(encrypted.toString("hex"))}, "hex")), decipher.final()]);\n` +
    `  await fetch(${JSON.stringify(`data:text/plain;base64,${Buffer.from(secrets.network).toString("base64")}`)}).then((response) => response.text());\n` +
    `  structuredClone({ value: String.fromCodePoint(...${JSON.stringify(points(secrets.clone))}) });\n` +
    `  const workerBoundary = await import("node:worker_threads"); const channel = new workerBoundary.MessageChannel(); channel.port1.postMessage(String.fromCodePoint(...${JSON.stringify(points(secrets.ipc))})); channel.port1.close(); channel.port2.close();\n` +
    `  atob(${JSON.stringify(Buffer.from(secrets.base64).toString("base64"))});\n` +
    `  process.stdout.write(String.fromCodePoint(...${JSON.stringify(points(secrets.output))}));\n` +
    `  await WebAssembly.compile(new Uint8Array([0,97,115,109,1,0,0,0]));\n` +
    `}\n`);
  const boundaryCanaries = path.join(directory, "boundary-canaries.json"); await writeFile(boundaryCanaries, JSON.stringify(Object.values(secrets)));
  const reportPath = path.join(directory, "probe.json"); const result = spawnSync(process.execPath, [probe, "--artifact", output, "--canaries", boundaryCanaries, "--virtualization-report", transformReport, "--report", reportPath], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 2, result.stderr); const report = JSON.parse(await readFile(reportPath, "utf8")); assert.equal(report.schemaVersion, 2); assert.equal(report.status, "recovered"); assert.equal(report.canaries.recovered, Object.keys(secrets).length);
  for (const name of ["base64-decode", "buffer-to-string", "crypto-decipher", "file-read", "ipc-post-message", "json-parse", "network-fetch", "process-output", "structured-clone", "text-decoder", "webassembly-input"]) { assert.equal(report.boundaryCoverage[name].installed, true, name); assert.ok(report.boundaryCoverage[name].calls > 0, name); }
});

test("runtime hook fails closed when an artifact floods the observation corpus", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-boundary-flood-")); const output = path.join(directory, "virtualized.mjs"); const transformReport = path.join(directory, "virtualization.json");
  const transformed = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", output, "--report", transformReport, "--seed", "8383", "--canaries", canaries], { encoding: "utf8" }); assert.equal(transformed.status, 0, transformed.stderr);
  await appendFile(output, "\nfor (let antiReaFlood = 0; antiReaFlood < 9000; antiReaFlood += 1) console.log('x');\n");
  const reportPath = path.join(directory, "probe.json"); const result = spawnSync(process.execPath, [probe, "--artifact", output, "--canaries", canaries, "--virtualization-report", transformReport, "--report", reportPath], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 1, result.stderr); const report = JSON.parse(await readFile(reportPath, "utf8")); assert.equal(report.status, "invalid"); assert.match(report.executionError, /observation limit exceeded/);
});
