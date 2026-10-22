#!/usr/bin/env node
import crypto, { createHash } from "node:crypto";
import fs from "node:fs";
import { open, readFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { MessagePort } from "node:worker_threads";

const MAX_OBSERVATION_BYTES = 32 * 1024 * 1024;
const MAX_OBSERVATIONS = 8192;
const MAX_VALUE_BYTES = 10 * 1024 * 1024;
const BOUNDARIES = [
  "base64-decode", "buffer-to-string", "crypto-decipher", "file-read", "ipc-post-message", "json-parse",
  "network-fetch", "process-output", "structured-clone", "text-decoder", "webassembly-input",
];

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: probe-vm-runtime.mjs --artifact FILE.js --canaries FILE.json --virtualization-report FILE.json --report NEW.json [--key-slot IDENTIFIER --key-env ENV_NAME]\n");
  process.exit(64);
}

function args(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) usage("invalid arguments");
    result[key.slice(2)] = value;
  }
  for (const name of ["artifact", "canaries", "virtualization-report", "report"]) if (!result[name]) usage(`--${name} is required`);
  if ((result["key-slot"] === undefined) !== (result["key-env"] === undefined)) usage("--key-slot and --key-env must be provided together");
  return result;
}

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }

async function main() {
  const options = args(process.argv.slice(2));
  const artifact = path.resolve(options.artifact);
  const reportPath = path.resolve(options.report);
  if (artifact === reportPath) throw new Error("artifact and report must differ");
  const canaries = JSON.parse(await readFile(options.canaries, "utf8"));
  if (!Array.isArray(canaries) || canaries.some((item) => typeof item !== "string" || item.length < 4)) throw new Error("invalid canary list");
  const virtualizationReport = JSON.parse(await readFile(options["virtualization-report"], "utf8"));
  const expectedFunctionIds = virtualizationReport?.functions?.map((item) => item?.id).sort();
  if (virtualizationReport?.transformer?.name !== "anti-rea-selective-vm" || !Array.isArray(expectedFunctionIds) || expectedFunctionIds.length < 1 || expectedFunctionIds.some((item) => !/^[a-f0-9]{64}$/.test(item)) || new Set(expectedFunctionIds).size !== expectedFunctionIds.length) throw new Error("virtualization report has invalid protected function coverage");
  const recoveredPrograms = [];
  const recoveredTexts = [];
  const boundaryCoverage = Object.fromEntries(BOUNDARIES.map((name) => [name, { installed: false, calls: 0, observations: 0 }]));
  let observedBytes = 0;
  let observationOverflow = false;
  const OriginalTextDecoder = globalThis.TextDecoder;
  const originalParse = JSON.parse;
  const originalStringify = JSON.stringify;
  const originalBufferToString = Buffer.prototype.toString;
  const originalLog = console.log;
  const originalAtob = globalThis.atob;
  const originalStructuredClone = globalThis.structuredClone;
  const originalFetch = globalThis.fetch;
  const originalResponseText = globalThis.Response?.prototype?.text;
  const originalResponseJson = globalThis.Response?.prototype?.json;
  const originalResponseArrayBuffer = globalThis.Response?.prototype?.arrayBuffer;
  const originalStdoutWrite = process.stdout.write;
  const originalStderrWrite = process.stderr.write;
  const originalReadFile = fs.readFile;
  const originalReadFileSync = fs.readFileSync;
  const originalPromiseReadFile = fs.promises.readFile;
  const originalCreateDecipheriv = crypto.createDecipheriv;
  const originalPostMessage = MessagePort.prototype.postMessage;
  const originalWasmCompile = globalThis.WebAssembly?.compile;
  const originalWasmInstantiate = globalThis.WebAssembly?.instantiate;

  function install(name) { boundaryCoverage[name].installed = true; }
  function observe(name, value) {
    boundaryCoverage[name].calls += 1;
    if (observationOverflow || value === undefined || value === null) return;
    let text;
    try {
      if (typeof value === "string") text = value;
      else if (Buffer.isBuffer(value)) text = originalBufferToString.call(value, "utf8");
      else if (value instanceof ArrayBuffer) text = originalBufferToString.call(Buffer.from(value), "utf8");
      else if (ArrayBuffer.isView(value)) text = originalBufferToString.call(Buffer.from(value.buffer, value.byteOffset, value.byteLength), "utf8");
      else if (typeof value === "object") text = originalStringify(value);
      else text = String(value);
    } catch { return; }
    if (typeof text !== "string") return;
    const bytes = Buffer.byteLength(text);
    if (bytes > MAX_VALUE_BYTES || recoveredTexts.length >= MAX_OBSERVATIONS || observedBytes + bytes > MAX_OBSERVATION_BYTES) { observationOverflow = true; return; }
    observedBytes += bytes; recoveredTexts.push(text); boundaryCoverage[name].observations += 1;
  }

  class ObservedTextDecoder extends OriginalTextDecoder {
    decode(...values) {
      const text = super.decode(...values);
      observe("text-decoder", text);
      return text;
    }
  }
  install("text-decoder");
  globalThis.TextDecoder = ObservedTextDecoder;
  JSON.parse = function observedParse(text, reviver) {
    const value = originalParse(text, reviver);
    observe("json-parse", text); observe("json-parse", value);
    if (value && typeof value === "object" && /^[a-f0-9]{64}$/.test(value.d ?? "") && Array.isArray(value.c) && Array.isArray(value.i)) recoveredPrograms.push(value);
    return value;
  };
  install("json-parse");
  Buffer.prototype.toString = function observedBufferToString(...values) { const text = originalBufferToString.apply(this, values); observe("buffer-to-string", text); return text; };
  install("buffer-to-string");
  if (typeof originalAtob === "function") { globalThis.atob = function observedAtob(...values) { const text = originalAtob.apply(this, values); observe("base64-decode", text); return text; }; install("base64-decode"); }
  if (typeof originalStructuredClone === "function") { globalThis.structuredClone = function observedStructuredClone(value, ...rest) { observe("structured-clone", value); const cloned = originalStructuredClone.call(this, value, ...rest); observe("structured-clone", cloned); return cloned; }; install("structured-clone"); }
  console.log = (...values) => { for (const value of values) observe("process-output", value); };
  process.stdout.write = function observedStdout(chunk, ...rest) { observe("process-output", chunk); return originalStdoutWrite.call(this, chunk, ...rest); };
  process.stderr.write = function observedStderr(chunk, ...rest) { observe("process-output", chunk); return originalStderrWrite.call(this, chunk, ...rest); };
  install("process-output");
  fs.readFile = function observedReadFile(...values) { const callbackIndex = values.length - 1; const callback = values[callbackIndex]; if (typeof callback === "function") values[callbackIndex] = function observedCallback(error, data) { if (!error) observe("file-read", data); return callback.apply(this, arguments); }; return originalReadFile.apply(this, values); };
  fs.readFileSync = function observedReadFileSync(...values) { const data = originalReadFileSync.apply(this, values); observe("file-read", data); return data; };
  fs.promises.readFile = async function observedPromiseReadFile(...values) { const data = await originalPromiseReadFile.apply(this, values); observe("file-read", data); return data; };
  syncBuiltinESMExports(); install("file-read");
  crypto.createDecipheriv = function observedCreateDecipheriv(...values) { const decipher = originalCreateDecipheriv.apply(this, values); for (const method of ["update", "final"]) { const original = decipher[method]; decipher[method] = function observedDecipherMethod(...methodValues) { const output = original.apply(this, methodValues); observe("crypto-decipher", output); return output; }; } return decipher; };
  syncBuiltinESMExports(); install("crypto-decipher");
  MessagePort.prototype.postMessage = function observedPostMessage(value, ...rest) { observe("ipc-post-message", value); return originalPostMessage.call(this, value, ...rest); };
  install("ipc-post-message");
  if (typeof originalWasmCompile === "function") { globalThis.WebAssembly.compile = function observedWasmCompile(value, ...rest) { observe("webassembly-input", value); return originalWasmCompile.call(this, value, ...rest); }; install("webassembly-input"); }
  if (typeof originalWasmInstantiate === "function") { globalThis.WebAssembly.instantiate = function observedWasmInstantiate(value, ...rest) { observe("webassembly-input", value); return originalWasmInstantiate.call(this, value, ...rest); }; install("webassembly-input"); }
  if (typeof originalFetch === "function") {
    globalThis.fetch = async function observedFetch(input, init) { observe("network-fetch", typeof input === "string" ? input : input?.url); observe("network-fetch", init?.body); const response = await originalFetch.call(this, input, init); try { observe("network-fetch", await response.clone().arrayBuffer()); } catch {} return response; };
    if (typeof originalResponseText === "function") globalThis.Response.prototype.text = async function observedResponseText(...values) { const value = await originalResponseText.apply(this, values); observe("network-fetch", value); return value; };
    if (typeof originalResponseJson === "function") globalThis.Response.prototype.json = async function observedResponseJson(...values) { const value = await originalResponseJson.apply(this, values); observe("network-fetch", value); return value; };
    if (typeof originalResponseArrayBuffer === "function") globalThis.Response.prototype.arrayBuffer = async function observedResponseArrayBuffer(...values) { const value = await originalResponseArrayBuffer.apply(this, values); observe("network-fetch", value); return value; };
    install("network-fetch");
  }
  let externalKeyInstalled = false;
  if (options["key-slot"] !== undefined) {
    if (!/^[A-Za-z_$][A-Za-z0-9_$]{3,63}$/.test(options["key-slot"]) || !/^[A-Z][A-Z0-9_]{2,63}$/.test(options["key-env"])) throw new Error("invalid external key slot or environment variable name");
    const raw = process.env[options["key-env"]];
    if (!/^[a-f0-9]{64}$/.test(raw ?? "")) throw new Error("external runtime key is missing or invalid");
    globalThis[options["key-slot"]] = () => Uint8Array.from(Buffer.from(raw, "hex"));
    externalKeyInstalled = true;
  }
  let executionError = null;
  try {
    await import(`${pathToFileURL(artifact).href}?anti-rea-probe=${Date.now()}`);
  } catch (error) {
    executionError = error instanceof Error ? error.message : String(error);
  } finally {
    globalThis.TextDecoder = OriginalTextDecoder;
    JSON.parse = originalParse;
    Buffer.prototype.toString = originalBufferToString;
    console.log = originalLog;
    if (typeof originalAtob === "function") globalThis.atob = originalAtob;
    if (typeof originalStructuredClone === "function") globalThis.structuredClone = originalStructuredClone;
    if (typeof originalFetch === "function") globalThis.fetch = originalFetch;
    if (typeof originalResponseText === "function") globalThis.Response.prototype.text = originalResponseText;
    if (typeof originalResponseJson === "function") globalThis.Response.prototype.json = originalResponseJson;
    if (typeof originalResponseArrayBuffer === "function") globalThis.Response.prototype.arrayBuffer = originalResponseArrayBuffer;
    process.stdout.write = originalStdoutWrite; process.stderr.write = originalStderrWrite;
    fs.readFile = originalReadFile; fs.readFileSync = originalReadFileSync; fs.promises.readFile = originalPromiseReadFile;
    crypto.createDecipheriv = originalCreateDecipheriv; MessagePort.prototype.postMessage = originalPostMessage;
    if (typeof originalWasmCompile === "function") globalThis.WebAssembly.compile = originalWasmCompile;
    if (typeof originalWasmInstantiate === "function") globalThis.WebAssembly.instantiate = originalWasmInstantiate;
    syncBuiltinESMExports();
    if (externalKeyInstalled) delete globalThis[options["key-slot"]];
  }
  const corpus = [...recoveredTexts, ...recoveredPrograms.map((item) => JSON.stringify(item))].join("\n");
  const recovered = canaries.filter((item) => corpus.includes(item));
  const observedFunctionIds = [...new Set(recoveredPrograms.map((item) => item.d))].sort();
  const coverageComplete = JSON.stringify(observedFunctionIds) === JSON.stringify(expectedFunctionIds);
  if (executionError === null && !coverageComplete) executionError = `incomplete protected function coverage: observed ${observedFunctionIds.length}/${expectedFunctionIds.length}`;
  if (executionError === null && observationOverflow) executionError = "runtime boundary observation limit exceeded";
  const report = {
    schemaVersion: 2,
    probe: "anti-rea-vm-runtime-hook",
    artifact: { path: artifact, sha256: sha256(await readFile(artifact)) },
    status: executionError ? "invalid" : recovered.length > 0 ? "recovered" : "not-recovered",
    executionError,
    decodedPrograms: recoveredPrograms.length,
    decodedTexts: recoveredTexts.length,
    boundaryCoverage,
    coverage: { expectedFunctionIds, observedFunctionIds, complete: coverageComplete },
    canaries: {
      supplied: canaries.length,
      suppliedSha256: canaries.map((item) => sha256(Buffer.from(item))).sort(),
      recovered: recovered.length,
      recoveredSha256: recovered.map((item) => sha256(Buffer.from(item))).sort(),
    },
    limitations: [
      "the probe observes common JavaScript decode boundaries and is not exhaustive",
      "not-recovered is not proof against debugger, CDP, Frida, V8, or function-boundary observation",
    ],
  };
  const handle = await open(reportPath, "wx", 0o644);
  try { await handle.writeFile(`${JSON.stringify(report, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (executionError) process.exitCode = 1;
  else if (recovered.length > 0) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`VM runtime probe error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
