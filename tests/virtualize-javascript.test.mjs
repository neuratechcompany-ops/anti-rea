import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { pathToFileURL } from "node:url";

const root = path.resolve(import.meta.dirname, "..");
const virtualizer = path.join(root, "scripts", "virtualize-javascript.mjs");
const transformer = path.join(root, "scripts", "transform-javascript.mjs");
const vmProfile = path.join(root, "profiles", "javascript-vm-balanced.json");
const input = path.join(root, "tests", "fixtures", "javascript-vm-owned.js");
const canaries = path.join(root, "tests", "fixtures", "javascript-vm-canaries.json");

async function virtualize(seed = "8128") {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-"));
  const output = path.join(directory, "virtualized.js");
  const report = path.join(directory, "report.json");
  const result = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", output, "--report", report, "--seed", seed, "--canaries", canaries], { encoding: "utf8", timeout: 30000 });
  return { directory, output, report, result };
}

test("virtualizes marked pure functions, removes body canaries, and preserves behavior", async () => {
  const baseline = spawnSync(process.execPath, [input], { encoding: "utf8" });
  assert.equal(baseline.status, 0, baseline.stderr);
  const current = await virtualize();
  assert.equal(current.result.status, 0, current.result.stderr);
  const protectedRun = spawnSync(process.execPath, [current.output], { encoding: "utf8" });
  assert.equal(protectedRun.status, 0, protectedRun.stderr);
  assert.equal(protectedRun.stdout, baseline.stdout);
  const output = await readFile(current.output, "utf8");
  for (const value of JSON.parse(await readFile(canaries, "utf8"))) assert.ok(!output.includes(value), `virtualized output leaked ${value}`);
  const report = JSON.parse(await readFile(current.report, "utf8"));
  assert.equal(report.functions.length, 1);
  assert.equal(report.functions[0].name, "calculateEnterpriseRisk");
  assert.equal(report.canaries.plaintextRecovered, 0);
  assert.ok(report.functions[0].instructions > 10);
});

test("different seeds diversify the encrypted program and opcode assignment", async () => {
  const first = await virtualize("1");
  const second = await virtualize("2");
  assert.equal(first.result.status, 0, first.result.stderr);
  assert.equal(second.result.status, 0, second.result.stderr);
  assert.notDeepEqual(await readFile(first.output), await readFile(second.output));
});

test("external-key mode omits the decryption key from the client and runs only after key provisioning", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-external-"));
  const output = path.join(directory, "virtualized.js");
  const report = path.join(directory, "report.json");
  const seed = "424242";
  const key = "01".repeat(32);
  const transformed = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", output, "--report", report, "--seed", seed, "--canaries", canaries, "--key-mode", "external", "--key-slot", "__ANTI_REA_TEST_KEY__", "--key-env", "ANTI_REA_TEST_BUILD_KEY"], { encoding: "utf8", env: { ...process.env, ANTI_REA_TEST_BUILD_KEY: key } });
  assert.equal(transformed.status, 0, transformed.stderr);
  const withoutKey = spawnSync(process.execPath, [output], { encoding: "utf8" });
  assert.equal(withoutKey.status, 1);
  assert.match(withoutKey.stderr, /protected program unavailable/);
  const baseline = spawnSync(process.execPath, [input], { encoding: "utf8" });
  const program = `let issued;globalThis.__ANTI_REA_TEST_KEY__=(functionId)=>{if(!/^[a-f0-9]{64}$/.test(functionId))throw Error("bad function id");issued=Uint8Array.from(Buffer.from(${JSON.stringify(key)},"hex"));return issued};await import(${JSON.stringify(pathToFileURL(output).href)});if(issued.some(Boolean))throw Error("provider key copy was not zeroed");`;
  const withKey = spawnSync(process.execPath, ["--input-type=module", "--eval", program], { encoding: "utf8" });
  assert.equal(withKey.status, 0, withKey.stderr);
  assert.equal(withKey.stdout, baseline.stdout);
  const source = await readFile(output, "utf8");
  assert.ok(!source.includes(key), "external decryption key leaked into the client artifact");
  assert.match(source, /q\.fill\(0\)/, "decrypted payload bytes are not cleared after decode");
  const payloadMatch = source.match(/Buffer\.from\("([A-Za-z0-9+/=]+)","base64"\)/);
  assert.ok(payloadMatch, "encrypted payload was not found");
  const modifiedPayload = Buffer.from(payloadMatch[1], "base64"); modifiedPayload[0] ^= 1;
  const tampered = path.join(directory, "tampered.js");
  await writeFile(tampered, source.replace(payloadMatch[1], modifiedPayload.toString("base64")));
  const tamperedProgram = `globalThis.__ANTI_REA_TEST_KEY__=()=>Uint8Array.from(Buffer.from(${JSON.stringify(key)},"hex"));await import(${JSON.stringify(pathToFileURL(tampered).href)});`;
  const tamperedRun = spawnSync(process.execPath, ["--input-type=module", "--eval", tamperedProgram], { encoding: "utf8" });
  assert.equal(tamperedRun.status, 1);
  assert.match(tamperedRun.stderr, /protected program authentication failed/);
  const receipt = JSON.parse(await readFile(report, "utf8"));
  assert.deepEqual(receipt.key.mode, "external");
  assert.equal(receipt.key.slot, "__ANTI_REA_TEST_KEY__");
  assert.equal(receipt.key.provider, "function-v1");
  assert.equal(receipt.key.encryption, "chacha20-poly1305");
  assert.match(receipt.functions[0].aadSha256, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(receipt).includes(key), "external key leaked into the stage receipt");
  const legacyString = spawnSync(process.execPath, ["--input-type=module", "--eval", `globalThis.__ANTI_REA_TEST_KEY__=${JSON.stringify(key)};await import(${JSON.stringify(`${pathToFileURL(output).href}?legacy-string`)});`], { encoding: "utf8" });
  assert.equal(legacyString.status, 1); assert.match(legacyString.stderr, /protected program unavailable/);
});

test("external-key mode rejects weak keys and randomizes nonce across otherwise identical builds", async () => {
  const key = "03".repeat(32);
  const outputs = [];
  for (let index = 0; index < 2; index += 1) {
    const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-nonce-"));
    const output = path.join(directory, "virtualized.js");
    const result = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", output, "--report", path.join(directory, "report.json"), "--seed", "77", "--key-mode", "external", "--key-slot", "__ANTI_REA_NONCE_KEY__", "--key-env", "ANTI_REA_NONCE_KEY"], { encoding: "utf8", env: { ...process.env, ANTI_REA_NONCE_KEY: key } });
    assert.equal(result.status, 0, result.stderr);
    outputs.push(await readFile(output));
  }
  assert.notDeepEqual(outputs[0], outputs[1]);

  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-weak-key-"));
  const weak = spawnSync(process.execPath, [virtualizer, "--input", input, "--output", path.join(directory, "out.js"), "--report", path.join(directory, "report.json"), "--seed", "77", "--key-mode", "external", "--key-slot", "__ANTI_REA_NONCE_KEY__", "--key-env", "ANTI_REA_NONCE_KEY"], { encoding: "utf8", env: { ...process.env, ANTI_REA_NONCE_KEY: "abcd" } });
  assert.equal(weak.status, 64);
  assert.match(weak.stderr, /32-byte lowercase hex/);
});

test("fails closed on unsupported closures instead of silently leaving marked code", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-vm-reject-"));
  const source = path.join(directory, "input.js");
  await writeFile(source, "const secret = 4; /* @anti-rea-vm */ function risky(value) { return value + secret; }\n");
  const result = spawnSync(process.execPath, [virtualizer, "--input", source, "--output", path.join(directory, "out.js"), "--report", path.join(directory, "report.json"), "--seed", "5"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /free identifier secret is forbidden/);
});

test("VM profile requires and cryptographically binds the virtualization report", async () => {
  const current = await virtualize("991");
  assert.equal(current.result.status, 0, current.result.stderr);
  const output = path.join(current.directory, "layered.js");
  const report = path.join(current.directory, "transform.json");
  const withoutEvidence = spawnSync(process.execPath, [transformer, "--input", current.output, "--output", output, "--profile", vmProfile, "--report", report, "--seed", "992"], { encoding: "utf8", timeout: 30000 });
  assert.equal(withoutEvidence.status, 1);
  assert.match(withoutEvidence.stderr, /requires a bound anti-rea-selective-vm stage/);

  const transformed = spawnSync(process.execPath, [transformer, "--input", current.output, "--output", output, "--profile", vmProfile, "--report", report, "--seed", "992", "--virtualization-report", current.report, "--canaries", canaries], { encoding: "utf8", timeout: 30000 });
  assert.equal(transformed.status, 0, transformed.stderr);
  const baseline = spawnSync(process.execPath, [input], { encoding: "utf8" });
  const protectedRun = spawnSync(process.execPath, [output], { encoding: "utf8", timeout: 10000 });
  assert.equal(protectedRun.status, 0, protectedRun.stderr);
  assert.equal(protectedRun.stdout, baseline.stdout);
  const transformReport = JSON.parse(await readFile(report, "utf8"));
  assert.equal(transformReport.upstream.virtualization.functions, 1);
  assert.equal(transformReport.profile.requiredPreviousStages[0], "anti-rea-selective-vm");
});
