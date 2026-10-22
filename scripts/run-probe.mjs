#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { constants as fsConstants, createReadStream } from "node:fs";
import { access, lstat, mkdir, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const ADAPTER_KEYS = new Set([
  "args", "command", "executableEnv", "family", "id", "outputFormat",
  "maxOutputBytes", "requireNonEmpty", "schemaVersion", "surfaces", "timeoutMs", "type",
]);

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: run-probe.mjs --adapter FILE --artifact PATH --evidence NEW_DIR\n");
  process.exit(64);
}

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) usage("invalid arguments");
    if (result[key.slice(2)] !== undefined) usage(`duplicate argument: ${key}`);
    result[key.slice(2)] = value;
  }
  if (!result.adapter || !result.artifact || !result.evidence) usage("all arguments are required");
  return result;
}

function loadAdapter(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("adapter must be an object");
  const unknown = Object.keys(value).filter((key) => !ADAPTER_KEYS.has(key));
  if (unknown.length > 0) throw new Error(`unknown adapter field(s): ${unknown.sort().join(", ")}`);
  if (value.schemaVersion !== 1 || value.type !== "probe") throw new Error("unsupported adapter schema or type");
  if (typeof value.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(value.id)) throw new Error("invalid adapter id");
  if (typeof value.family !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(value.family)) throw new Error("invalid adapter family");
  if (!Array.isArray(value.surfaces) || value.surfaces.length === 0 || value.surfaces.some((item) => typeof item !== "string" || !item)) throw new Error("surfaces must be a nonempty string array");
  if (!Array.isArray(value.args) || value.args.some((item) => typeof item !== "string")) throw new Error("args must be a string array");
  if ((typeof value.command === "string") === (typeof value.executableEnv === "string")) throw new Error("adapter must specify exactly one of command or executableEnv");
  if (value.executableEnv !== undefined && !/^[A-Z][A-Z0-9_]{1,63}$/.test(value.executableEnv)) throw new Error("invalid executableEnv");
  if (!Number.isSafeInteger(value.timeoutMs) || value.timeoutMs < 100 || value.timeoutMs > 3_600_000) throw new Error("timeoutMs must be 100..3600000");
  if (!Number.isSafeInteger(value.maxOutputBytes) || value.maxOutputBytes < 1024 || value.maxOutputBytes > 512 * 1024 * 1024) throw new Error("maxOutputBytes must be 1024..536870912");
  if (!new Set(["json", "text"]).has(value.outputFormat)) throw new Error("outputFormat must be json or text");
  if (typeof value.requireNonEmpty !== "boolean") throw new Error("requireNonEmpty must be boolean");
  return value;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function resolveExecutable(command) {
  if (!command) return null;
  const candidates = command.includes(path.sep)
    ? [path.resolve(command)]
    : (process.env.PATH ?? "").split(path.delimiter).filter(Boolean).map((directory) => path.join(directory, command));
  for (const candidate of candidates) {
    try {
      await access(candidate, fsConstants.X_OK);
      return await realpath(candidate);
    } catch {}
  }
  return null;
}

async function digestFile(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function identifyArtifact(value) {
  const root = await realpath(value);
  const stat = await lstat(root);
  if (stat.isFile()) return { kind: "file", sha256: await digestFile(root) };
  if (!stat.isDirectory()) throw new Error("artifact must be a regular file or directory");
  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      if (entry.isSymbolicLink()) throw new Error(`artifact contains a symlink: ${relative}`);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile()) {
        const bytes = await readFile(absolute);
        files.push({ path: relative, bytes: bytes.length, sha256: digest(bytes) });
      } else throw new Error(`artifact contains unsupported entry: ${relative}`);
    }
  }
  await visit(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { kind: "directory", sha256: digest(Buffer.from(files.map((item) => `${item.path}\0${item.bytes}\0${item.sha256}`).join("\n"))) };
}

function replaceArgs(args, artifact) {
  return args.map((value) => value.replaceAll("{artifact}", artifact));
}

function sanitizedProbeEnvironment() {
  const allowed = ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "WINDIR"];
  return Object.fromEntries(allowed.filter((name) => typeof process.env[name] === "string").map((name) => [name, process.env[name]]));
}

function run(command, args, timeoutMs, maxOutputBytes) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    let timedOut = false;
    let outputLimitExceeded = false;
    let spawnError;
    // Analyzer output is untrusted and the analyzer itself may be compromised.
    // Never expose build keys, signer passphrases, cloud credentials, or the
    // executable-selection environment variable to it.
    const child = spawn(command, args, { env: sanitizedProbeEnvironment(), shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    const collect = (destination, chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > maxOutputBytes) {
        outputLimitExceeded = true;
        child.kill("SIGKILL");
        return;
      }
      destination.push(chunk);
    };
    child.stdout?.on("data", (chunk) => collect(stdout, chunk));
    child.stderr?.on("data", (chunk) => collect(stderr, chunk));
    child.on("error", (error) => { spawnError = error; });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.on("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({
        durationMs: Number(process.hrtime.bigint() - started) / 1_000_000,
        exitCode,
        signal,
        spawnError,
        timedOut,
        outputLimitExceeded,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      });
    });
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const adapterPath = path.resolve(args.adapter);
  const artifact = path.resolve(args.artifact);
  const evidence = path.resolve(args.evidence);
  const adapterRaw = await readFile(adapterPath);
  const adapter = loadAdapter(JSON.parse(adapterRaw.toString("utf8")));
  const command = adapter.command ?? process.env[adapter.executableEnv];
  const executablePath = await resolveExecutable(command);
  const executableSha256 = executablePath === null ? null : await digestFile(executablePath);
  const artifactIdentityBefore = await identifyArtifact(artifact);

  await mkdir(evidence, { recursive: false });
  let execution;
  if (!command) {
    execution = { durationMs: 0, exitCode: null, signal: null, spawnError: new Error(`${adapter.executableEnv} is not configured`), timedOut: false, outputLimitExceeded: false, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
  } else {
    execution = await run(command, replaceArgs(adapter.args, artifact), adapter.timeoutMs, adapter.maxOutputBytes);
  }
  const artifactIdentityAfter = await identifyArtifact(artifact);

  await writeFile(path.join(evidence, "stdout.bin"), execution.stdout, { flag: "wx" });
  await writeFile(path.join(evidence, "stderr.bin"), execution.stderr, { flag: "wx" });

  const reasons = [];
  let status = "valid";
  if (execution.spawnError) {
    status = "blocked";
    reasons.push(execution.spawnError.message);
  } else if (execution.timedOut) {
    status = "invalid";
    reasons.push("probe timed out");
  } else if (execution.outputLimitExceeded) {
    status = "invalid";
    reasons.push("probe exceeded its output byte limit");
  } else if (execution.exitCode !== 0) {
    status = "invalid";
    reasons.push(`probe exited with code ${execution.exitCode}`);
  } else if (adapter.requireNonEmpty && execution.stdout.length === 0) {
    status = "invalid";
    reasons.push("probe produced empty stdout");
  } else if (adapter.outputFormat === "json") {
    try {
      JSON.parse(execution.stdout.toString("utf8"));
    } catch {
      status = "invalid";
      reasons.push("probe stdout is not valid JSON");
    }
  }
  if (artifactIdentityBefore.kind !== artifactIdentityAfter.kind || artifactIdentityBefore.sha256 !== artifactIdentityAfter.sha256) {
    status = "invalid";
    reasons.push("artifact changed while the probe was running");
  }

  const report = {
    schemaVersion: 1,
    adapter: { id: adapter.id, family: adapter.family, sha256: digest(adapterRaw), surfaces: adapter.surfaces },
    artifact,
    artifactIdentity: artifactIdentityBefore,
    invocation: { command: command ?? null, executable: executablePath === null ? null : { path: executablePath, sha256: executableSha256 }, args: replaceArgs(adapter.args, artifact), timeoutMs: adapter.timeoutMs, maxOutputBytes: adapter.maxOutputBytes },
    status,
    reasons,
    execution: { exitCode: execution.exitCode, signal: execution.signal, timedOut: execution.timedOut, outputLimitExceeded: execution.outputLimitExceeded, durationMs: Math.round(execution.durationMs * 1000) / 1000 },
    evidence: {
      stdout: { path: "stdout.bin", bytes: execution.stdout.length, sha256: digest(execution.stdout) },
      stderr: { path: "stderr.bin", bytes: execution.stderr.length, sha256: digest(execution.stderr) },
    },
  };
  await writeFile(path.join(evidence, "probe.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (status === "invalid") process.exitCode = 2;
  if (status === "blocked") process.exitCode = 3;
}

main().catch((error) => {
  process.stderr.write(`probe runner error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
