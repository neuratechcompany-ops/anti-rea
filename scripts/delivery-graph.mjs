#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { brotliDecompressSync, gunzipSync } from "node:zlib";

const KINDS = new Set(["release", "update", "crash", "support", "symbols"]);
const AUDIENCES = new Set(["customer", "internal"]);
const SOURCE_EXTENSIONS = new Set([".coffee", ".cts", ".jsx", ".mts", ".svelte", ".ts", ".tsx", ".vue"]);
const SYMBOL_EXTENSIONS = new Set([".dwarf", ".dsym", ".pdb"]);
const ARCHIVE_EXTENSIONS = new Set([".7z", ".apk", ".bz2", ".ipa", ".rar", ".tar", ".tgz", ".xz", ".zip"]);
const SENSITIVE_NAMES = new Set([".env", ".git", ".npmrc", ".yarnrc", "id_dsa", "id_ed25519", "id_rsa"]);
const SENSITIVE_EXTENSIONS = new Set([".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"]);
const CONTENT_RULES = [
  ["private-key", /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/],
  ["aws-access-key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ["github-token", /\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}\b/],
  ["credential-assignment", /\b(?:api[_-]?key|client[_-]?secret|password|private[_-]?key|secret|token)\b\s*[:=]\s*["'][^"'\r\n]{12,}["']/i],
];

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
}
function safeId(value, label) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9._-]{1,63}$/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

export function validateDeliveryDescriptor(value) {
  exactKeys(value, ["schemaVersion", "surfaces"], "delivery descriptor");
  if (value.schemaVersion !== 1 || !Array.isArray(value.surfaces) || value.surfaces.length < 2 || value.surfaces.length > 32) throw new Error("delivery descriptor is invalid");
  const ids = new Set(); const kinds = new Set(); const paths = new Set();
  for (const [index, surface] of value.surfaces.entries()) {
    exactKeys(surface, ["audience", "id", "kind", "path"], `delivery descriptor surfaces[${index}]`);
    safeId(surface.id, `delivery descriptor surfaces[${index}].id`);
    if (ids.has(surface.id)) throw new Error(`duplicate delivery surface id: ${surface.id}`);
    ids.add(surface.id);
    if (!KINDS.has(surface.kind) || kinds.has(surface.kind) || !AUDIENCES.has(surface.audience) || typeof surface.path !== "string" || !surface.path || surface.path.includes("\0") || paths.has(surface.path)) throw new Error(`delivery descriptor surfaces[${index}] is invalid or aliases another surface`);
    kinds.add(surface.kind); paths.add(surface.path);
  }
  return value;
}

export async function inspectDeliverySurface(surface, limits = {}) {
  const maxFiles = limits.maxFiles ?? 20_000;
  const maxFileBytes = limits.maxFileBytes ?? 32 * 1024 * 1024;
  const root = await realpath(surface.path);
  if (!(await lstat(root)).isDirectory()) throw new Error(`delivery surface ${surface.id} must be a directory`);
  const files = [];
  const findings = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      const lower = entry.name.toLowerCase();
      if (entry.isSymbolicLink()) { findings.push({ path: relative, rule: "symlink" }); continue; }
      if (entry.isDirectory()) {
        if (SENSITIVE_NAMES.has(lower) || (surface.audience === "customer" && lower.endsWith(".dsym"))) findings.push({ path: relative, rule: lower.endsWith(".dsym") ? "debug-symbol-directory" : "sensitive-directory" });
        await visit(absolute);
      } else if (entry.isFile()) {
        files.push({ absolute, relative });
        if (files.length > maxFiles) throw new Error(`delivery surface ${surface.id} exceeds maxFiles (${maxFiles})`);
      } else findings.push({ path: relative, rule: "unsupported-file-type" });
    }
  }
  await visit(root);
  let totalBytes = 0;
  const identities = [];
  for (const file of files) {
    const stat = await lstat(file.absolute);
    if (stat.size > maxFileBytes) { findings.push({ path: file.relative, rule: "file-size-limit" }); continue; }
    const bytes = await readFile(file.absolute);
    totalBytes += bytes.length;
    identities.push({ path: file.relative, bytes: bytes.length, sha256: sha256(bytes) });
    const basename = path.basename(file.relative).toLowerCase();
    const extension = path.extname(basename);
    const logicalBasename = new Set([".br", ".gz"]).has(extension) ? path.basename(basename, extension) : basename;
    const logicalExtension = path.extname(logicalBasename);
    if (SENSITIVE_NAMES.has(basename) || basename.startsWith(".env.") || SENSITIVE_EXTENSIONS.has(extension)) findings.push({ path: file.relative, rule: "sensitive-file" });
    if (ARCHIVE_EXTENSIONS.has(extension)) findings.push({ path: file.relative, rule: "uninspected-archive" });
    if (surface.audience === "customer") {
      if (SOURCE_EXTENSIONS.has(logicalExtension)) findings.push({ path: file.relative, rule: "source-file" });
      if (logicalExtension === ".map") findings.push({ path: file.relative, rule: "source-map-file" });
      if (SYMBOL_EXTENSIONS.has(extension)) findings.push({ path: file.relative, rule: "debug-symbol-file" });
    }
    const representations = [bytes];
    const gzip = extension === ".gz" || (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b);
    if (gzip || extension === ".br") {
      try { representations.push(gzip ? gunzipSync(bytes, { maxOutputLength: maxFileBytes }) : brotliDecompressSync(bytes, { maxOutputLength: maxFileBytes })); }
      catch { findings.push({ path: file.relative, rule: "compressed-content-invalid" }); }
    }
    for (const representation of representations) {
      const text = representation.toString("utf8");
      if (surface.audience === "customer" && /[#@]\s*sourceMappingURL\s*=|["']sourcesContent["']\s*:/.test(text)) findings.push({ path: file.relative, rule: "embedded-source-reference" });
      for (const [rule, pattern] of CONTENT_RULES) if (pattern.test(text)) findings.push({ path: file.relative, rule });
    }
  }
  identities.sort((a, b) => a.path.localeCompare(b.path));
  const uniqueFindings = [...new Map(findings.map((item) => [`${item.path}\0${item.rule}`, item])).values()];
  uniqueFindings.sort((a, b) => a.path.localeCompare(b.path) || a.rule.localeCompare(b.rule));
  const treeSha256 = sha256(Buffer.from(identities.map((item) => `${item.path}\0${item.bytes}\0${item.sha256}`).join("\n")));
  return { id: surface.id, kind: surface.kind, audience: surface.audience, path: root, treeSha256, files: identities.length, bytes: totalBytes, findings: uniqueFindings };
}

export async function inspectDeliveryGraph(descriptor) {
  validateDeliveryDescriptor(descriptor);
  const surfaces = [];
  for (const surface of descriptor.surfaces) surfaces.push(await inspectDeliverySurface(surface));
  const normalizedDescriptor = { schemaVersion: 1, surfaces: surfaces.map(({ id, kind, audience, path: surfacePath }) => ({ id, kind, audience, path: surfacePath })) };
  validateDeliveryDescriptor(normalizedDescriptor);
  return { schemaVersion: 1, descriptorSha256: sha256(Buffer.from(JSON.stringify(normalizedDescriptor))), status: surfaces.some((item) => item.findings.length > 0) ? "FAIL" : "PASS", surfaces };
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: delivery-graph.mjs --descriptor FILE --report FILE\n");
  process.exit(64);
}
function args(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || result[key.slice(2)] !== undefined) usage("invalid arguments");
    result[key.slice(2)] = value;
  }
  if (!result.descriptor || !result.report) usage("--descriptor and --report are required");
  return result;
}
async function main() {
  const options = args(process.argv.slice(2));
  const descriptor = validateDeliveryDescriptor(JSON.parse(await readFile(path.resolve(options.descriptor), "utf8")));
  const report = await inspectDeliveryGraph(descriptor);
  const destination = path.resolve(options.report);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o644 });
  process.stdout.write(`${JSON.stringify({ status: report.status, report: destination, surfaces: report.surfaces.length }, null, 2)}\n`);
  if (report.status !== "PASS") process.exitCode = 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => {
  process.stderr.write(`delivery graph error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
