#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { open, readFile, realpath } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  return value;
}
const canonical = (value) => Buffer.from(JSON.stringify(canonicalValue(value)));
function args(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) { const key = argv[index]; const value = argv[index + 1]; if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) throw new Error("invalid arguments"); result[key.slice(2)] = value; }
  for (const name of ["artifact", "reference", "candidate", "corpus", "report"]) if (!result[name]) throw new Error(`--${name} is required`);
  result["timeout-ms"] ??= "5000";
  if (!/^[1-9][0-9]{2,5}$/.test(result["timeout-ms"]) || Number(result["timeout-ms"]) > 60000) throw new Error("--timeout-ms must be 100..60000");
  return result;
}
function sanitizedEnvironment() {
  const allowed = ["LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "WINDIR"];
  return Object.fromEntries(allowed.filter((name) => typeof process.env[name] === "string").map((name) => [name, process.env[name]]));
}
function execute(runtime, modulePath, input, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(runtime, [modulePath], { cwd: os.tmpdir(), env: sanitizedEnvironment(), shell: false, stdio: ["pipe", "pipe", "pipe"] });
    const stdout = []; const stderr = []; let bytes = 0; let timedOut = false; let overflow = false; let spawnError = null;
    const collect = (target, chunk) => { bytes += chunk.length; if (bytes > 64 * 1024) { overflow = true; child.kill("SIGKILL"); } else target.push(chunk); };
    child.stdout.on("data", (chunk) => collect(stdout, chunk)); child.stderr.on("data", (chunk) => collect(stderr, chunk)); child.on("error", (error) => { spawnError = error; });
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs);
    child.on("close", (exitCode, signal) => { clearTimeout(timer); resolve({ exitCode, signal, timedOut, overflow, spawnError, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) }); });
    child.stdin.end(`${JSON.stringify(input)}\n`);
  });
}
async function vector(runtime, modulePath, corpus, timeoutMs) {
  const cases = []; let error = null;
  for (const input of corpus) {
    const inputSha256 = sha256(canonical(input)); const result = await execute(runtime, modulePath, input, timeoutMs);
    if (result.spawnError || result.timedOut || result.overflow || result.exitCode !== 0) { error = `${path.basename(modulePath)} failed for ${inputSha256}: ${result.spawnError?.message ?? (result.timedOut ? "timeout" : result.overflow ? "output limit" : `exit ${result.exitCode}`)}`; break; }
    let output;
    try { output = JSON.parse(result.stdout.toString("utf8")); } catch { error = `${path.basename(modulePath)} returned non-JSON for ${inputSha256}`; break; }
    cases.push({ inputSha256, outputSha256: sha256(canonical(output)), status: "returned" });
  }
  cases.sort((left, right) => left.inputSha256.localeCompare(right.inputSha256));
  return { vector: { schemaVersion: 1, cases }, error };
}

async function main() {
  const options = args(process.argv.slice(2)); const runtime = await realpath(process.execPath);
  const artifact = await realpath(path.resolve(options.artifact)); const reference = await realpath(path.resolve(options.reference)); const candidate = await realpath(path.resolve(options.candidate));
  const identitiesBefore = { artifact: sha256(await readFile(artifact)), runtime: sha256(await readFile(runtime)), reference: sha256(await readFile(reference)), candidate: sha256(await readFile(candidate)) };
  const corpusBytes = await readFile(path.resolve(options.corpus)); const corpus = JSON.parse(corpusBytes.toString("utf8"));
  if (!Array.isArray(corpus) || corpus.length === 0 || corpus.length > 256 || corpus.some((item) => item === undefined) || new Set(corpus.map((item) => sha256(canonical(item)))).size !== corpus.length) throw new Error("corpus must contain 1..256 unique JSON cases");
  const timeoutMs = Number(options["timeout-ms"]); const referenceResult = await vector(runtime, reference, corpus, timeoutMs); const candidateResult = referenceResult.error ? { vector: { schemaVersion: 1, cases: [] }, error: "reference failed" } : await vector(runtime, candidate, corpus, timeoutMs);
  const identitiesAfter = { artifact: sha256(await readFile(artifact)), runtime: sha256(await readFile(runtime)), reference: sha256(await readFile(reference)), candidate: sha256(await readFile(candidate)) };
  const changedIdentity = Object.keys(identitiesBefore).find((name) => identitiesBefore[name] !== identitiesAfter[name]);
  const executionError = referenceResult.error ?? candidateResult.error ?? (changedIdentity ? `${changedIdentity} changed during holdout execution` : null); const complete = executionError === null && referenceResult.vector.cases.length === corpus.length && candidateResult.vector.cases.length === corpus.length;
  const equivalent = complete && JSON.stringify(referenceResult.vector) === JSON.stringify(candidateResult.vector);
  const report = { schemaVersion: 1, probe: "anti-rea-behavior-holdout", artifact: { path: artifact, sha256: identitiesBefore.artifact }, runtime: { path: runtime, sha256: identitiesBefore.runtime }, reference: { path: reference, sha256: identitiesBefore.reference, behavior: referenceResult.vector }, candidate: { path: candidate, sha256: identitiesBefore.candidate, behavior: candidateResult.vector }, corpus: { sha256: sha256(corpusBytes), cases: corpus.length, inputSha256: corpus.map((item) => sha256(canonical(item))).sort() }, coverage: { expectedCases: corpus.length, referenceCases: referenceResult.vector.cases.length, candidateCases: candidateResult.vector.cases.length, complete }, status: executionError ? "invalid" : equivalent ? "recovered" : "not-recovered", executionError, limitations: ["candidate execution must occur in an external network-denied filesystem-restricted sandbox", "holdout equivalence covers only the supplied owner corpus"] };
  const destination = path.resolve(options.report); const handle = await open(destination, "wx", 0o644); try { await handle.writeFile(`${JSON.stringify(report, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`); if (executionError) process.exitCode = 1; else if (equivalent) process.exitCode = 2;
}
main().catch((error) => { process.stderr.write(`behavior holdout probe error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
