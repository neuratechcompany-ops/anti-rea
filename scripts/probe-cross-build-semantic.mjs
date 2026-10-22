#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { access, lstat, open, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { canonicalizeSemanticIr } from "./semantic-ir.mjs";

const MIN_VARIANTS = 20;
const MAX_VARIANTS = 64;
const CONSENSUS_RATIO = 0.8;
const JACCARD_THRESHOLD = 0.7;
const MAX_VARIANT_BYTES = 8 * 1024 * 1024;
const ADAPTER_KEYS = ["args", "command", "executableEnv", "family", "id", "maxOutputBytes", "outputFormat", "requireNonEmpty", "schemaVersion", "surfaces", "timeoutMs", "type"];
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const rounded = (value) => Math.round(value * 1_000_000) / 1_000_000;
const exactKeys = (value, keys, label) => { if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`); };

async function resolveExecutable(command) {
  const candidates = command.includes(path.sep) ? [path.resolve(command)] : (process.env.PATH ?? "").split(path.delimiter).filter(Boolean).map((directory) => path.join(directory, command));
  for (const candidate of candidates) try { await access(candidate, fsConstants.X_OK); return await realpath(candidate); } catch {}
  throw new Error("semantic IR extractor executable is unavailable");
}

async function loadAdapter(adapterValue) {
  const adapterPath = await realpath(adapterValue); const bytes = await readFile(adapterPath); const value = JSON.parse(bytes.toString("utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !ADAPTER_KEYS.includes(key))) throw new Error("semantic adapter fields are invalid");
  for (const key of ADAPTER_KEYS.filter((item) => item !== "command" && item !== "executableEnv")) if (!(key in value)) throw new Error("semantic adapter fields are incomplete");
  if (value.schemaVersion !== 1 || value.type !== "probe" || value.family !== "semantic-ir" || value.outputFormat !== "json" || value.requireNonEmpty !== true) throw new Error("semantic adapter identity is invalid");
  if (typeof value.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(value.id) || !Array.isArray(value.surfaces) || value.surfaces.length === 0 || value.surfaces.some((item) => typeof item !== "string" || !item)) throw new Error("semantic adapter metadata is invalid");
  if (!Array.isArray(value.args) || value.args.length !== 1 || value.args[0] !== "{artifact}") throw new Error("semantic adapter must pass only the artifact path to the pinned executable");
  if ((typeof value.command === "string") === (typeof value.executableEnv === "string")) throw new Error("semantic adapter must select exactly one executable source");
  if (value.executableEnv !== undefined && !/^[A-Z][A-Z0-9_]{1,63}$/.test(value.executableEnv)) throw new Error("semantic adapter executableEnv is invalid");
  if (!Number.isSafeInteger(value.timeoutMs) || value.timeoutMs < 100 || value.timeoutMs > 600000 || !Number.isSafeInteger(value.maxOutputBytes) || value.maxOutputBytes < 1024 || value.maxOutputBytes > 16 * 1024 * 1024) throw new Error("semantic adapter resource limits are invalid");
  const command = value.command ?? process.env[value.executableEnv]; if (!command) throw new Error(`${value.executableEnv} is not configured`);
  const executable = await resolveExecutable(command); const executableBytes = await readFile(executable);
  return { value, path: adapterPath, sha256: sha256(bytes), executable, executableSha256: sha256(executableBytes) };
}

function sanitizedEnvironment() {
  const names = ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "WINDIR"];
  return Object.fromEntries(names.filter((name) => typeof process.env[name] === "string").map((name) => [name, process.env[name]]));
}

function runExtractor(adapter, artifact) {
  return new Promise((resolve, reject) => {
    const args = adapter.value.args.map((item) => item.replace("{artifact}", artifact)); const child = spawn(adapter.executable, args, { env: sanitizedEnvironment(), shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const stdout = []; const stderr = []; let bytes = 0; let exceeded = false; let timedOut = false; let settled = false;
    const collect = (target, chunk) => { bytes += chunk.length; if (bytes > adapter.value.maxOutputBytes) { exceeded = true; child.kill("SIGKILL"); } else target.push(chunk); };
    child.stdout.on("data", (chunk) => collect(stdout, chunk)); child.stderr.on("data", (chunk) => collect(stderr, chunk)); child.on("error", (error) => { if (!settled) { settled = true; clearTimeout(timer); reject(error); } });
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, adapter.value.timeoutMs);
    child.on("close", (code, signal) => { if (settled) return; settled = true; clearTimeout(timer); const out = Buffer.concat(stdout); const err = Buffer.concat(stderr); if (timedOut || exceeded || code !== 0 || signal !== null || out.length === 0) reject(new Error(`semantic extractor failed: timeout=${timedOut} outputLimit=${exceeded} exit=${code} signal=${signal} stderrSha256=${sha256(err)}`)); else resolve(out); });
  });
}

function jaccard(left, right) { let intersection = 0; for (const item of left) if (right.has(item)) intersection += 1; return intersection / (left.size + right.size - intersection); }

export async function analyzeCrossBuildSemantic(artifactValue, variantValues, adapterValue) {
  if (!Array.isArray(variantValues) || variantValues.length < MIN_VARIANTS || variantValues.length > MAX_VARIANTS) throw new Error(`semantic corpus requires ${MIN_VARIANTS}..${MAX_VARIANTS} variants`);
  const artifact = await realpath(artifactValue); if (!(await lstat(artifact)).isFile()) throw new Error("semantic target must be a regular file"); const adapter = await loadAdapter(adapterValue);
  const paths = new Set(); const identities = new Set(); const variants = []; const semantic = []; let artifactIndex = -1;
  for (const [index, item] of variantValues.entries()) {
    exactKeys(item, ["attestation", "path"], `semantic variants[${index}]`); const variant = await realpath(item.path); const attestation = await realpath(item.attestation); const stat = await lstat(variant);
    if (!stat.isFile() || stat.size < 1 || stat.size > MAX_VARIANT_BYTES || paths.has(variant)) throw new Error(`semantic variant ${index} is invalid or duplicate`);
    const before = await readFile(variant); const identity = sha256(before); if (identities.has(identity)) throw new Error("semantic corpus contains duplicate bytes"); paths.add(variant); identities.add(identity);
    const attestationBytes = await readFile(attestation); const rawIr = await runExtractor(adapter, variant); let canonical;
    try { canonical = canonicalizeSemanticIr(JSON.parse(rawIr.toString("utf8"))); } catch (error) { throw new Error(`semantic variant ${index} output is invalid: ${error instanceof Error ? error.message : String(error)}`); }
    if (sha256(await readFile(variant)) !== identity || sha256(await readFile(attestation)) !== sha256(attestationBytes)) throw new Error(`semantic variant ${index} changed during extraction`);
    variants.push({ path: variant, sha256: identity, bytes: before.length, attestation: { path: attestation, sha256: sha256(attestationBytes) }, irSha256: sha256(rawIr), fingerprint: canonical.fingerprint, featureSetSha256: canonical.featureSetSha256, featureCount: canonical.features.length, nodeCount: canonical.nodeCount, edgeCount: canonical.edgeCount }); semantic.push(canonical);
    if (variant === artifact) artifactIndex = index;
  }
  if (artifactIndex === -1) throw new Error("semantic corpus does not contain the release artifact");
  for (const [index, variant] of variants.entries()) {
    if (sha256(await readFile(variant.path)) !== variant.sha256 || sha256(await readFile(variant.attestation.path)) !== variant.attestation.sha256) throw new Error(`semantic variant ${index} or its attestation changed after extraction`);
  }
  const fingerprintSupport = new Map(); for (const item of semantic) fingerprintSupport.set(item.fingerprint, (fingerprintSupport.get(item.fingerprint) ?? 0) + 1);
  const minSupport = Math.ceil(semantic.length * CONSENSUS_RATIO); const target = semantic[artifactIndex]; const alignedVariants = fingerprintSupport.get(target.fingerprint) ?? 0; let maximumPairwiseFeatureJaccard = 0;
  for (let left = 0; left < semantic.length; left += 1) for (let right = left + 1; right < semantic.length; right += 1) maximumPairwiseFeatureJaccard = Math.max(maximumPairwiseFeatureJaccard, jaccard(new Set(semantic[left].features), new Set(semantic[right].features)));
  const analysis = { minSupport, targetFingerprint: target.fingerprint, targetFeatureSetSha256: target.featureSetSha256, targetFeatures: target.features.length, alignedVariants, maximumPairwiseFeatureJaccard: rounded(maximumPairwiseFeatureJaccard) };
  const recovered = alignedVariants >= minSupport || analysis.maximumPairwiseFeatureJaccard > JACCARD_THRESHOLD;
  if (sha256(await readFile(adapter.path)) !== adapter.sha256 || sha256(await readFile(adapter.executable)) !== adapter.executableSha256) throw new Error("semantic adapter or extractor changed during analysis");
  return {
    schemaVersion: 1, probe: "anti-rea-cross-build-semantic", artifact: { path: artifact, sha256: variants[artifactIndex].sha256 }, variants,
    tool: { family: "semantic-ir", adapter: { path: adapter.path, sha256: adapter.sha256 }, executable: { path: adapter.executable, sha256: adapter.executableSha256 } },
    coverage: { expectedVariants: variants.length, observedVariants: variants.length, complete: true }, thresholds: { consensusRatio: CONSENSUS_RATIO, maximumPairwiseFeatureJaccard: JACCARD_THRESHOLD }, analysis,
    status: recovered ? "recovered" : "not-recovered", executionError: null,
    limitations: ["semantic recovery depends on the pinned extractor and its supported input surfaces", "graph refinement is a bounded structural signal, not a proof of program equivalence"],
  };
}

function usage(message) { if (message) process.stderr.write(`${message}\n`); process.stderr.write("usage: probe-cross-build-semantic.mjs --artifact FILE --manifest FILE --adapter FILE --report NEW.json\n"); process.exit(64); }
function args(argv) { const value = {}; for (let index = 0; index < argv.length; index += 2) { const key = argv[index]; const item = argv[index + 1]; if (!key?.startsWith("--") || item === undefined || value[key.slice(2)] !== undefined) usage("invalid arguments"); value[key.slice(2)] = item; } if (Object.keys(value).sort().join("\0") !== ["adapter", "artifact", "manifest", "report"].sort().join("\0")) usage("all arguments are required"); return value; }
async function main() {
  const options = args(process.argv.slice(2)); const manifestPath = path.resolve(options.manifest); const manifest = JSON.parse(await readFile(manifestPath, "utf8")); exactKeys(manifest, ["schemaVersion", "variants"], "semantic manifest"); if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.variants)) throw new Error("semantic manifest is invalid");
  const root = path.dirname(manifestPath); const variants = manifest.variants.map((item, index) => { exactKeys(item, ["attestation", "path"], `semantic manifest variants[${index}]`); if (typeof item.path !== "string" || !item.path || typeof item.attestation !== "string" || !item.attestation) throw new Error(`semantic manifest variants[${index}] is invalid`); return { path: path.resolve(root, item.path), attestation: path.resolve(root, item.attestation) }; });
  const report = await analyzeCrossBuildSemantic(path.resolve(options.artifact), variants, path.resolve(options.adapter)); const destination = path.resolve(options.report); const handle = await open(destination, "wx", 0o644); try { await handle.writeFile(`${JSON.stringify(report, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({ status: report.status, report: destination, variants: report.variants.length, analysis: report.analysis }, null, 2)}\n`); if (report.status === "recovered") process.exitCode = 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`semantic cross-build probe error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
