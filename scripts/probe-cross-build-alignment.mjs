#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const WINDOW_BYTES = 32;
const STRIDE_BYTES = 8;
const MAX_VARIANT_BYTES = 8 * 1024 * 1024;
const MIN_VARIANTS = 20;
const MAX_VARIANTS = 64;
const STABLE_RATIO_THRESHOLD = 0.10;
const JACCARD_THRESHOLD = 0.25;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
};

function windows(bytes) {
  if (bytes.length < WINDOW_BYTES) throw new Error(`variant must contain at least ${WINDOW_BYTES} bytes`);
  const values = new Set();
  for (let offset = 0; offset <= bytes.length - WINDOW_BYTES; offset += STRIDE_BYTES) {
    const window = bytes.subarray(offset, offset + WINDOW_BYTES);
    if (new Set(window).size < 8) continue;
    values.add(sha256(window));
  }
  if (values.size === 0) throw new Error("variant has no analyzable high-entropy windows");
  return values;
}

function rounded(value) { return Math.round(value * 1_000_000) / 1_000_000; }

export async function analyzeCrossBuildAlignment(artifactValue, variantValues) {
  if (!Array.isArray(variantValues) || variantValues.length < MIN_VARIANTS || variantValues.length > MAX_VARIANTS) throw new Error(`cross-build corpus requires ${MIN_VARIANTS}..${MAX_VARIANTS} variants`);
  const artifact = await realpath(artifactValue);
  if (!(await lstat(artifact)).isFile()) throw new Error("cross-build artifact must be a file");
  const variants = []; const sets = []; const paths = new Set(); const identities = new Set(); let artifactIndex = -1;
  for (const [index, value] of variantValues.entries()) {
    exactKeys(value, ["attestation", "path"], `cross-build variants[${index}]`);
    const variant = await realpath(value.path); const attestationPath = await realpath(value.attestation);
    if (paths.has(variant)) throw new Error("cross-build corpus contains a duplicate path");
    paths.add(variant);
    const stat = await lstat(variant); if (!stat.isFile() || stat.size > MAX_VARIANT_BYTES) throw new Error(`variant ${index} is not a bounded regular file`);
    const bytes = await readFile(variant); const identity = sha256(bytes);
    if (identities.has(identity)) throw new Error("cross-build corpus contains duplicate bytes");
    const attestationBytes = await readFile(attestationPath);
    identities.add(identity); variants.push({ path: variant, sha256: identity, bytes: bytes.length, attestation: { path: attestationPath, sha256: sha256(attestationBytes) } }); sets.push(windows(bytes));
    if (variant === artifact) artifactIndex = index;
  }
  if (artifactIndex === -1) throw new Error("cross-build corpus does not contain the release artifact");
  const support = new Map();
  for (const set of sets) for (const hash of set) support.set(hash, (support.get(hash) ?? 0) + 1);
  const minSupport = Math.ceil(sets.length * 0.8);
  const stable = [...support].filter(([, count]) => count >= minSupport).map(([hash]) => hash).sort();
  const target = sets[artifactIndex]; const stableInTarget = [...target].filter((hash) => (support.get(hash) ?? 0) >= minSupport).length;
  let maximumPairwiseJaccard = 0;
  for (let left = 0; left < sets.length; left += 1) for (let right = left + 1; right < sets.length; right += 1) {
    let intersection = 0; for (const hash of sets[left]) if (sets[right].has(hash)) intersection += 1;
    maximumPairwiseJaccard = Math.max(maximumPairwiseJaccard, intersection / (sets[left].size + sets[right].size - intersection));
  }
  const analysis = {
    windowBytes: WINDOW_BYTES, strideBytes: STRIDE_BYTES, minSupport, targetWindows: target.size,
    stableWindows: stableInTarget, stableWindowSetSha256: sha256(Buffer.from(stable.join("\n"))),
    stableByteRatio: rounded(stableInTarget / target.size), maximumPairwiseJaccard: rounded(maximumPairwiseJaccard),
  };
  for (const variant of variants) {
    if (sha256(await readFile(variant.path)) !== variant.sha256) throw new Error("cross-build variant changed during analysis");
    if (sha256(await readFile(variant.attestation.path)) !== variant.attestation.sha256) throw new Error("cross-build variant attestation changed during analysis");
  }
  const artifactIdentity = variants[artifactIndex];
  const recovered = analysis.stableByteRatio > STABLE_RATIO_THRESHOLD || analysis.maximumPairwiseJaccard > JACCARD_THRESHOLD;
  return {
    schemaVersion: 1, probe: "anti-rea-cross-build-alignment", artifact: { path: artifact, sha256: artifactIdentity.sha256 }, variants,
    coverage: { expectedVariants: variants.length, observedVariants: variants.length, complete: true },
    thresholds: { maximumStableByteRatio: STABLE_RATIO_THRESHOLD, maximumPairwiseJaccard: JACCARD_THRESHOLD },
    analysis, status: recovered ? "recovered" : "not-recovered", executionError: null,
    limitations: ["variants must be independently produced protected-function regions, not whole runtimes or containers", "byte-window alignment does not prove semantic non-equivalence"],
  };
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: probe-cross-build-alignment.mjs --artifact FILE --manifest FILE --report FILE\n"); process.exit(64);
}
function args(argv) {
  const result = {}; for (let index = 0; index < argv.length; index += 2) { const key = argv[index]; const value = argv[index + 1]; if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) usage("invalid arguments"); result[key.slice(2)] = value; }
  if (!result.artifact || !result.manifest || !result.report || Object.keys(result).some((key) => !new Set(["artifact", "manifest", "report"]).has(key))) usage("all arguments are required"); return result;
}
async function main() {
  const options = args(process.argv.slice(2)); const manifest = JSON.parse(await readFile(path.resolve(options.manifest), "utf8"));
  exactKeys(manifest, ["schemaVersion", "variants"], "cross-build manifest"); if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.variants)) throw new Error("cross-build manifest is invalid");
  const manifestRoot = path.dirname(path.resolve(options.manifest)); const variants = manifest.variants.map((item, index) => { exactKeys(item, ["attestation", "path"], `cross-build manifest variants[${index}]`); if (typeof item.path !== "string" || !item.path || item.path.includes("\0") || typeof item.attestation !== "string" || !item.attestation || item.attestation.includes("\0")) throw new Error(`cross-build manifest variants[${index}] is invalid`); return { path: path.resolve(manifestRoot, item.path), attestation: path.resolve(manifestRoot, item.attestation) }; });
  const report = await analyzeCrossBuildAlignment(path.resolve(options.artifact), variants);
  const destination = path.resolve(options.report); await mkdir(path.dirname(destination), { recursive: true }); await writeFile(destination, `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o644 });
  process.stdout.write(`${JSON.stringify({ status: report.status, report: destination, variants: report.variants.length, analysis: report.analysis }, null, 2)}\n`); if (report.status === "recovered") process.exitCode = 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`cross-build probe error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
