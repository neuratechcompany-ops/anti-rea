#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { webcrack } from "webcrack";
import { recognizeVmEnvelopes, recognizeVmFunctionIds, recoverCanaries, unpackVmPayloads } from "../../scripts/unpack-vm-payload.mjs";

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: probe.mjs --artifact FILE.js --canaries FILE.json --virtualization-report FILE.json --report NEW.json\n");
  process.exit(64);
}

function args(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) usage("invalid arguments");
    result[key.slice(2)] = value;
  }
  for (const name of ["artifact", "canaries", "virtualization-report", "report"]) if (!result[name]) usage(`--${name} is required`);
  return result;
}

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
async function fileSha256(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function packageVersion() {
  const entry = fileURLToPath(import.meta.resolve("webcrack"));
  let directory = path.dirname(entry);
  for (;;) {
    const candidate = path.join(directory, "package.json");
    try {
      const value = JSON.parse(await readFile(candidate, "utf8"));
      if (value.name === "webcrack") return { version: value.version, root: directory, entry, packageJson: candidate };
    } catch {}
    const parent = path.dirname(directory);
    if (parent === directory) throw new Error("cannot resolve webcrack package identity");
    directory = parent;
  }
}

async function main() {
  const options = args(process.argv.slice(2));
  const artifact = await realpath(path.resolve(options.artifact));
  const reportPath = path.resolve(options.report);
  if (artifact === reportPath) throw new Error("artifact and report must differ");
  const source = await readFile(artifact, "utf8");
  const canaries = JSON.parse(await readFile(options.canaries, "utf8"));
  if (!Array.isArray(canaries) || canaries.length === 0 || canaries.some((item) => typeof item !== "string" || item.length < 4)) throw new Error("invalid canary list");
  const virtualizationReport = JSON.parse(await readFile(options["virtualization-report"], "utf8"));
  const expectedFunctionIds = virtualizationReport?.functions?.map((item) => item?.id).sort();
  if (virtualizationReport?.transformer?.name !== "anti-rea-selective-vm" || !Array.isArray(expectedFunctionIds) || expectedFunctionIds.length < 1 || expectedFunctionIds.some((item) => !/^[a-f0-9]{64}$/.test(item)) || new Set(expectedFunctionIds).size !== expectedFunctionIds.length) throw new Error("virtualization report has invalid protected function coverage");
  let executionError = null;
  let deobfuscated = "";
  let programs = [];
  let envelopes = [];
  let observedFunctionIds = [];
  try {
    const result = await webcrack(source, { unpack: false });
    deobfuscated = result.code;
    envelopes = recognizeVmEnvelopes(deobfuscated);
    programs = unpackVmPayloads(deobfuscated);
    observedFunctionIds = [...new Set([...recognizeVmFunctionIds(source), ...recognizeVmFunctionIds(deobfuscated), ...programs.map((item) => item.functionId)])].sort();
    if (envelopes.length === 0) executionError = "public deobfuscator produced no recognizable Anti-REA VM envelope";
  } catch (error) {
    executionError = error instanceof Error ? error.message : String(error);
  }
  const recovered = recoverCanaries(programs, canaries);
  const coverageComplete = JSON.stringify(observedFunctionIds) === JSON.stringify(expectedFunctionIds);
  if (executionError === null && !coverageComplete) executionError = `incomplete protected function coverage: observed ${observedFunctionIds.length}/${expectedFunctionIds.length}`;
  const nodePath = await realpath(process.execPath);
  const installedPackage = await packageVersion();
  const lockfile = path.join(path.dirname(fileURLToPath(import.meta.url)), "pnpm-lock.yaml");
  const report = {
    schemaVersion: 1,
    probe: "anti-rea-vm-public-deobfuscator",
    artifact: { path: artifact, sha256: sha256(Buffer.from(source)) },
    status: executionError ? "invalid" : recovered.length > 0 ? "recovered" : "not-recovered",
    executionError,
    decodedPrograms: programs.length,
    decodedTexts: 0,
    recognizedEnvelopes: envelopes.length,
    coverage: { expectedFunctionIds, observedFunctionIds, complete: coverageComplete },
    canaries: {
      supplied: canaries.length,
      suppliedSha256: canaries.map((item) => sha256(Buffer.from(item))).sort(),
      recovered: recovered.length,
      recoveredSha256: recovered.map((item) => sha256(Buffer.from(item))).sort(),
    },
    tool: {
      name: "webcrack",
      version: installedPackage.version,
      node: process.versions.node,
      executable: { path: nodePath, sha256: await fileSha256(nodePath) },
      package: {
        root: installedPackage.root,
        entry: { path: installedPackage.entry, sha256: await fileSha256(installedPackage.entry) },
        manifest: { path: installedPackage.packageJson, sha256: await fileSha256(installedPackage.packageJson) },
        lockfile: { path: lockfile, sha256: await fileSha256(lockfile) },
      },
      deobfuscatedSha256: deobfuscated ? sha256(Buffer.from(deobfuscated)) : null,
    },
    limitations: [
      "webcrack may evaluate selected decoder fragments inside isolated-vm; run only against owned artifacts in an isolated analysis environment",
      "failure to recognize a payload is invalid evidence, not proof of protection",
      "canary recovery measures declared facts and does not enumerate all recoverable semantics",
    ],
  };
  const handle = await open(reportPath, "wx", 0o644);
  try { await handle.writeFile(`${JSON.stringify(report, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (executionError) process.exitCode = 1;
  else if (recovered.length > 0) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`public deobfuscator probe error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
