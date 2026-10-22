#!/usr/bin/env node
import { createHash } from "node:crypto";
import { open, readFile, unlink } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import bytenode from "bytenode";

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: compile-node-bytecode.mjs --input PROTECTED.js --transform-report REPORT.json --bytecode NEW.jsc --loader NEW.cjs --report NEW.json [--canaries FILE.json]\n");
  process.exit(64);
}

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) usage("invalid arguments");
    const name = key.slice(2);
    if (result[name] !== undefined) usage(`duplicate argument: ${key}`);
    result[name] = value;
  }
  for (const name of ["input", "transform-report", "bytecode", "loader", "report"]) if (!result[name]) usage(`--${name} is required`);
  return result;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function writeExclusive(destination, content) {
  const handle = await open(destination, "wx", 0o644);
  try {
    await handle.writeFile(content);
  } finally {
    await handle.close();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const inputPath = path.resolve(args.input);
  const bytecodePath = path.resolve(args.bytecode);
  const loaderPath = path.resolve(args.loader);
  const reportPath = path.resolve(args.report);
  if (new Set([inputPath, bytecodePath, loaderPath, reportPath]).size !== 4) throw new Error("input and output paths must all differ");
  if (path.dirname(bytecodePath) !== path.dirname(loaderPath)) throw new Error("bytecode and loader must share a directory");
  if (path.extname(bytecodePath) !== ".jsc" || path.extname(loaderPath) !== ".cjs") throw new Error("bytecode must use .jsc and loader must use .cjs");

  const input = await readFile(inputPath);
  if (input.length === 0 || input.length > 100 * 1024 * 1024) throw new Error("input must contain 1..104857600 bytes");
  const source = input.toString("utf8");
  if (Buffer.from(source, "utf8").length !== input.length) throw new Error("input must be valid UTF-8 JavaScript");
  const transformReportBytes = await readFile(args["transform-report"]);
  const transformReport = JSON.parse(transformReportBytes.toString("utf8"));
  if (transformReport?.schemaVersion !== 1 || transformReport?.output?.sha256 !== sha256(input)) throw new Error("transform report does not bind the bytecode input");
  if (!Array.isArray(transformReport?.profile?.compatibleNextStages) || !transformReport.profile.compatibleNextStages.includes("node-bytecode")) throw new Error("transform profile is not compatible with node-bytecode");
  const canaries = args.canaries === undefined ? [] : JSON.parse(await readFile(args.canaries, "utf8"));
  if (!Array.isArray(canaries) || canaries.some((item) => typeof item !== "string" || item.length < 4 || item.length > 1024)) throw new Error("canaries must be an array of strings, each 4..1024 characters");

  const started = process.hrtime.bigint();
  const bytecode = bytenode.compileCode(source, true);
  const durationMs = Number(process.hrtime.bigint() - started) / 1_000_000;
  const leakedCanaries = canaries.filter((item) => bytecode.includes(Buffer.from(item)));
  if (leakedCanaries.length > 0) throw new Error(`bytecode retains ${leakedCanaries.length} plaintext canary value(s)`);
  const loader = Buffer.from([
    "'use strict';",
    "const path = require('node:path');",
    "const bytenode = require('bytenode');",
    `bytenode.runBytecodeFile(path.join(__dirname, ${JSON.stringify(path.basename(bytecodePath))}));`,
    "",
  ].join("\n"), "utf8");
  const report = {
    schemaVersion: 1,
    compiler: { name: "bytenode", version: "1.7.0", compression: "brotli" },
    transformReport: { path: path.resolve(args["transform-report"]), sha256: sha256(transformReportBytes), profile: transformReport.profile.id },
    runtimeBinding: { node: process.versions.node, v8: process.versions.v8, platform: process.platform, arch: process.arch },
    input: { path: inputPath, bytes: input.length, sha256: sha256(input) },
    bytecode: { path: bytecodePath, bytes: bytecode.length, sha256: sha256(bytecode) },
    loader: { path: loaderPath, bytes: loader.length, sha256: sha256(loader), runtimeDependency: "bytenode@1.7.0" },
    canaries: { supplied: canaries.length, plaintextRecovered: leakedCanaries.length },
    compileDurationMs: Math.round(durationMs * 1000) / 1000,
    limitations: [
      "V8 bytecode is bound to the recorded Node/V8 platform and architecture",
      "bytecode can still be disassembled, hooked, patched, and observed at runtime",
      "this compiler targets Node scripts; Electron main, renderer, preload, and worker contexts require context-matched compilation",
      "Function.prototype.toString-dependent code and some arrow-function contexts may be incompatible",
    ],
  };

  const created = [];
  try {
    await writeExclusive(bytecodePath, bytecode); created.push(bytecodePath);
    await writeExclusive(loaderPath, loader); created.push(loaderPath);
    await writeExclusive(reportPath, `${JSON.stringify(report, null, 2)}\n`); created.push(reportPath);
  } catch (error) {
    for (const file of created.reverse()) await unlink(file).catch(() => {});
    throw error;
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`bytecode compile error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
