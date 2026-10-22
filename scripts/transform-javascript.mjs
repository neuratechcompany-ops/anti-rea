#!/usr/bin/env node
import { createHash } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import JavaScriptObfuscator from "javascript-obfuscator";

const PROFILE_KEYS = new Set(["compatibleNextStages", "id", "limits", "options", "requiredPreviousStages", "schemaVersion", "surfaces", "transformer"]);
const FORBIDDEN_OPTIONS = new Set([
  "debugProtectionInterval", "disableConsoleOutput", "domainLock",
  "sourceMap", "sourceMapMode", "sourceMapSourcesMode",
]);

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: transform-javascript.mjs --input BUNDLE.js --output NEW.js --profile PROFILE.json --report NEW.json --seed INTEGER [--canaries FILE.json] [--virtualization-report REPORT.json]\n");
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
  for (const name of ["input", "output", "profile", "report", "seed"]) if (result[name] === undefined) usage(`--${name} is required`);
  if (!/^(0|[1-9][0-9]{0,9})$/.test(result.seed) || Number(result.seed) > 0xffffffff) usage("--seed must be an integer from 0 to 4294967295");
  return result;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function loadProfile(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("profile must be an object");
  const unknown = Object.keys(value).filter((key) => !PROFILE_KEYS.has(key));
  if (unknown.length > 0) throw new Error(`unknown profile field(s): ${unknown.sort().join(", ")}`);
  if (value.schemaVersion !== 1 || value.transformer !== "javascript-obfuscator") throw new Error("unsupported profile schema or transformer");
  if (typeof value.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(value.id)) throw new Error("invalid profile id");
  if (!Array.isArray(value.surfaces) || value.surfaces.length === 0 || value.surfaces.some((item) => typeof item !== "string" || !item)) throw new Error("profile surfaces must be a nonempty string array");
  if (!Array.isArray(value.compatibleNextStages) || value.compatibleNextStages.some((item) => typeof item !== "string" || !item)) throw new Error("compatibleNextStages must be a string array");
  if (value.requiredPreviousStages !== undefined && (!Array.isArray(value.requiredPreviousStages) || value.requiredPreviousStages.some((item) => typeof item !== "string" || !item))) throw new Error("requiredPreviousStages must be a string array");
  if (!value.limits || typeof value.limits !== "object" || Array.isArray(value.limits) || Object.keys(value.limits).sort().join("|") !== "maxFixedOverheadBytes|maxInputBytes|maxSizeRatio") throw new Error("profile limits are invalid");
  if (!Number.isSafeInteger(value.limits.maxInputBytes) || value.limits.maxInputBytes < 1024 || value.limits.maxInputBytes > 100 * 1024 * 1024) throw new Error("maxInputBytes is invalid");
  if (!Number.isSafeInteger(value.limits.maxFixedOverheadBytes) || value.limits.maxFixedOverheadBytes < 0 || value.limits.maxFixedOverheadBytes > 10 * 1024 * 1024) throw new Error("maxFixedOverheadBytes is invalid");
  if (typeof value.limits.maxSizeRatio !== "number" || value.limits.maxSizeRatio < 1 || value.limits.maxSizeRatio > 100) throw new Error("maxSizeRatio is invalid");
  if (!value.options || typeof value.options !== "object" || Array.isArray(value.options)) throw new Error("profile options must be an object");
  for (const key of Object.keys(value.options)) {
    if (key.startsWith("vm")) throw new Error("remote/pro VM options are not allowed in the local transformer");
    if (FORBIDDEN_OPTIONS.has(key)) throw new Error(`framework owns unsafe or evidence-affecting option: ${key}`);
  }
  return value;
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
  const outputPath = path.resolve(args.output);
  const reportPath = path.resolve(args.report);
  if (new Set([inputPath, outputPath, reportPath]).size !== 3) throw new Error("input, output, and report paths must differ");
  const profileBytes = await readFile(args.profile);
  const profile = loadProfile(JSON.parse(profileBytes.toString("utf8")));
  const input = await readFile(inputPath);
  if (input.length > profile.limits.maxInputBytes) throw new Error(`input exceeds profile maxInputBytes (${profile.limits.maxInputBytes})`);
  const source = input.toString("utf8");
  if (Buffer.from(source, "utf8").length !== input.length) throw new Error("input must be valid UTF-8 JavaScript");
  if (/sourceMappingURL\s*=/.test(source)) throw new Error("input bundle still references a source map");

  let virtualization = null;
  if (args["virtualization-report"] !== undefined) {
    const reportPath = path.resolve(args["virtualization-report"]);
    const bytes = await readFile(reportPath);
    const value = JSON.parse(bytes.toString("utf8"));
    if (value?.schemaVersion !== 1 || value?.transformer?.name !== "anti-rea-selective-vm") throw new Error("invalid virtualization report identity");
    if (value?.output?.sha256 !== sha256(input)) throw new Error("virtualization report does not bind the transform input");
    if (!Array.isArray(value.functions) || value.functions.length === 0) throw new Error("virtualization report contains no protected functions");
    if (!Array.isArray(value?.canaries?.sha256) || value.canaries.sha256.some((item) => typeof item !== "string" || !/^[a-f0-9]{64}$/.test(item))) throw new Error("virtualization report has invalid canary evidence");
    virtualization = { path: reportPath, sha256: sha256(bytes), functions: value.functions.length, outputSha256: value.output.sha256, canarySha256: value.canaries.sha256 };
  }
  const requiredPreviousStages = profile.requiredPreviousStages ?? [];
  if (requiredPreviousStages.includes("anti-rea-selective-vm") && virtualization === null) throw new Error("profile requires a bound anti-rea-selective-vm stage");
  const unknownRequiredStages = requiredPreviousStages.filter((item) => item !== "anti-rea-selective-vm");
  if (unknownRequiredStages.length > 0) throw new Error(`unsupported required previous stage(s): ${unknownRequiredStages.join(", ")}`);

  const canaries = args.canaries === undefined ? [] : JSON.parse(await readFile(args.canaries, "utf8"));
  if (!Array.isArray(canaries) || canaries.some((item) => typeof item !== "string" || item.length < 4 || item.length > 1024)) throw new Error("canaries must be an array of strings, each 4..1024 characters");
  if (new Set(canaries).size !== canaries.length) throw new Error("canaries must be unique");
  const upstreamCanaryHashes = new Set(virtualization?.canarySha256 ?? []);
  const absentFromInput = canaries.filter((item) => !source.includes(item) && !upstreamCanaryHashes.has(sha256(Buffer.from(item))));
  if (absentFromInput.length > 0) throw new Error(`canaries absent from input: ${absentFromInput.length}`);

  const seed = Number(args.seed);
  const prefix = `_rg_${sha256(Buffer.from(`${profile.id}\0${seed}\0${sha256(input)}`)).slice(0, 10)}_`;
  const options = {
    ...profile.options,
    seed,
    identifiersPrefix: prefix,
    sourceMap: false,
    disableConsoleOutput: false,
    debugProtection: false,
  };
  const started = process.hrtime.bigint();
  const result = JavaScriptObfuscator.obfuscate(source, options);
  const output = Buffer.from(result.getObfuscatedCode(), "utf8");
  const durationMs = Number(process.hrtime.bigint() - started) / 1_000_000;
  const sizeRatio = input.length === 0 ? 0 : output.length / input.length;
  const sizeBudgetBytes = Math.ceil(input.length * profile.limits.maxSizeRatio + profile.limits.maxFixedOverheadBytes);
  if (output.length > sizeBudgetBytes) throw new Error(`output size ${output.length} exceeds profile budget ${sizeBudgetBytes}`);
  const leakedCanaries = canaries.filter((item) => output.includes(Buffer.from(item)));
  if (leakedCanaries.length > 0) throw new Error(`transformed artifact retains ${leakedCanaries.length} plaintext canary value(s)`);

  const report = {
    schemaVersion: 1,
    transformer: { name: "javascript-obfuscator", version: JavaScriptObfuscator.version },
    profile: { id: profile.id, sha256: sha256(profileBytes), surfaces: profile.surfaces, requiredPreviousStages, compatibleNextStages: profile.compatibleNextStages },
    upstream: { virtualization },
    seed,
    input: { path: inputPath, bytes: input.length, sha256: sha256(input) },
    output: { path: outputPath, bytes: output.length, sha256: sha256(output), sizeRatio: Math.round(sizeRatio * 1000) / 1000, sizeBudgetBytes },
    canaries: { supplied: canaries.length, plaintextRecovered: leakedCanaries.length },
    transformDurationMs: Math.round(durationMs * 1000) / 1000,
    limitations: [
      "output remains JavaScript and can be observed and instrumented at runtime",
      "canary absence proves only that supplied exact plaintext values are absent",
      "semantic equivalence and runtime recovery require separate probes",
    ],
  };
  await writeExclusive(outputPath, output);
  try {
    await writeExclusive(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    const { unlink } = await import("node:fs/promises");
    await unlink(outputPath);
    throw error;
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`javascript transform error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
