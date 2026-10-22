#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { brotliDecompressSync, gunzipSync } from "node:zlib";

const SOURCE_EXTENSIONS = new Set([
  ".coffee", ".cts", ".jsx", ".mts", ".svelte", ".ts", ".tsx", ".vue",
]);
const SENSITIVE_FILENAMES = new Set([
  ".env", ".env.local", ".env.production", ".git", ".npmrc", ".yarnrc",
  "id_dsa", "id_ed25519", "id_rsa",
]);
const SENSITIVE_EXTENSIONS = new Set([".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"]);
const ARCHIVE_EXTENSIONS = new Set([".7z", ".apk", ".bz2", ".ipa", ".rar", ".tar", ".tgz", ".xz", ".zip"]);
const SECRET_RULES = [
  ["private-key", /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/g],
  ["aws-access-key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ["github-token", /\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}\b/g],
  ["stripe-live-key", /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g],
  ["jwt-literal", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
  ["credential-assignment", /\b(?:api[_-]?key|client[_-]?secret|password|private[_-]?key|secret|token)\b\s*[:=]\s*["'][^"'\r\n]{12,}["']/gi],
];
const URL_PATTERN = /(?:https?|wss?):\/\/[A-Za-z0-9._~%!$&'()*+,;=:-]+(?::\d{1,5})?(?:\/[A-Za-z0-9._~%!$&'()*+,;=:@/?#\[\]-]*)?/g;
const PROTOCOL_RELATIVE_PATTERN = /["'`](\/\/[A-Za-z0-9.-]+(?::\d{1,5})?(?:\/[A-Za-z0-9._~%!$&'()*+,;=:@/?#\[\]-]*)?)/g;
const BASE64_PATTERN = /(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){6,}(?:==|=)?(?![A-Za-z0-9+/])/g;
const ASSEMBLED_CREDENTIAL_PATTERN = /\b(api[_-]?key|client[_-]?secret|password|private[_-]?key|secret|token)\b\s*[:=]\s*((?:["'](?:\\.|[^"'\\]){1,128}["']\s*\+\s*)+["'](?:\\.|[^"'\\]){1,128}["'])/gi;
const CONCATENATED_LITERALS_PATTERN = /(?:["'](?:\\.|[^"'\\]){1,256}["']\s*\+\s*)+["'](?:\\.|[^"'\\]){1,256}["']/g;
const ARRAY_JOIN_PATTERN = /\[((?:\s*["'](?:\\.|[^"'\\]){1,256}["']\s*,)+\s*["'](?:\\.|[^"'\\]){1,256}["']\s*)\]\s*\.join\(\s*["']["']\s*\)/g;
const FROM_CHAR_CODE_PATTERN = /String\.fromCharCode\(\s*([0-9,\s]{1,4096})\s*\)/g;
const REVERSED_LITERAL_PATTERN = /(["'])(.{6,4096}?)\1\s*\.split\(\s*["']["']\s*\)\s*\.reverse\(\s*\)\s*\.join\(\s*["']["']\s*\)/g;
const POLICY_KEYS = new Set([
  "allowedFiles", "allowedHosts", "denySourceFiles", "denySourceMaps", "forbiddenSubstrings",
  "maxFileBytes", "maxFiles", "requiredHosts", "version",
]);

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: verify-web-artifact.mjs --artifact DIR --report FILE [--policy FILE]\n");
  process.exit(64);
}

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) usage("invalid arguments");
    result[key.slice(2)] = value;
  }
  if (!result.artifact || !result.report) usage("--artifact and --report are required");
  return result;
}

function parsePolicyJson(raw) {
  const keys = new Set();
  let depth = 0;
  let expectingKey = false;
  for (let index = 0; index < raw.length; index += 1) {
    const character = raw[index];
    if (character === "{") {
      depth += 1;
      if (depth === 1) expectingKey = true;
      continue;
    }
    if (character === "}") {
      depth -= 1;
      continue;
    }
    if (character === "," && depth === 1) {
      expectingKey = true;
      continue;
    }
    if (character !== '"') continue;
    const start = index;
    index += 1;
    let escaped = false;
    for (; index < raw.length; index += 1) {
      if (escaped) escaped = false;
      else if (raw[index] === "\\") escaped = true;
      else if (raw[index] === '"') break;
    }
    if (!expectingKey || depth !== 1) continue;
    let cursor = index + 1;
    while (/\s/.test(raw[cursor] ?? "")) cursor += 1;
    if (raw[cursor] !== ":") continue;
    const key = JSON.parse(raw.slice(start, index + 1));
    if (keys.has(key)) throw new Error(`duplicate policy field: ${key}`);
    keys.add(key);
    expectingKey = false;
  }
  return JSON.parse(raw);
}

function validateRelativePath(value) {
  if (!value || value.startsWith("/") || value.includes("\\") || value.includes("\0")) return false;
  const parts = value.split("/");
  return parts.every((part) => part && part !== "." && part !== "..") && path.posix.normalize(value) === value;
}

function validatePolicy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("policy must be an object");
  const unknownKeys = Object.keys(value).filter((key) => !POLICY_KEYS.has(key));
  if (unknownKeys.length > 0) throw new Error(`unknown policy field(s): ${unknownKeys.sort().join(", ")}`);
  if (value.version !== undefined && (!Number.isSafeInteger(value.version) || value.version !== 1)) throw new Error("unsupported policy version");
  if (value.allowedFiles !== undefined && (!Array.isArray(value.allowedFiles) || value.allowedFiles.some((item) => typeof item !== "string" || !validateRelativePath(item)))) {
    throw new Error("allowedFiles must be an array of safe relative paths");
  }
  if (value.allowedFiles !== undefined && new Set(value.allowedFiles).size !== value.allowedFiles.length) {
    throw new Error("allowedFiles must not contain duplicates");
  }
  if (value.allowedHosts !== undefined && (!Array.isArray(value.allowedHosts) || value.allowedHosts.some((item) => typeof item !== "string"))) {
    throw new Error("allowedHosts must be an array of strings");
  }
  if (value.requiredHosts !== undefined && (!Array.isArray(value.requiredHosts) || value.requiredHosts.some((item) => typeof item !== "string"))) {
    throw new Error("requiredHosts must be an array of strings");
  }
  if (value.forbiddenSubstrings !== undefined && (!Array.isArray(value.forbiddenSubstrings) || value.forbiddenSubstrings.some((item) => typeof item !== "string"))) {
    throw new Error("forbiddenSubstrings must be an array of strings");
  }
  for (const key of ["maxFiles", "maxFileBytes"]) {
    if (value[key] !== undefined && (!Number.isSafeInteger(value[key]) || value[key] <= 0)) {
      throw new Error(`${key} must be a positive integer`);
    }
  }
  return {
    version: 1,
    denySourceMaps: value.denySourceMaps !== false,
    denySourceFiles: value.denySourceFiles !== false,
    allowedFiles: value.allowedFiles ?? null,
    allowedHosts: value.allowedHosts ?? null,
    requiredHosts: value.requiredHosts ?? [],
    forbiddenSubstrings: value.forbiddenSubstrings ?? [],
    maxFiles: value.maxFiles ?? 10_000,
    maxFileBytes: value.maxFileBytes ?? 20 * 1024 * 1024,
  };
}

function redactedEvidence(text, start, length) {
  const before = text.slice(Math.max(0, start - 18), start).replace(/[\r\n\t]+/g, " ");
  const after = text.slice(start + length, start + length + 18).replace(/[\r\n\t]+/g, " ");
  return `${before}[REDACTED:${length}]${after}`;
}

function lineNumber(text, offset) {
  let line = 1;
  for (let index = 0; index < offset; index += 1) if (text.charCodeAt(index) === 10) line += 1;
  return line;
}

function decodeSimpleEscapes(value) {
  return value
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\([\\/"'])/g, "$1");
}

function quotedFragments(value) {
  const fragments = [];
  const pattern = /'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"/g;
  for (const match of value.matchAll(pattern)) fragments.push(decodeSimpleEscapes(match[1] ?? match[2] ?? ""));
  return fragments;
}

function printableRatio(value) {
  if (value.length === 0) return 0;
  let printable = 0;
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) printable += 1;
  }
  return printable / value.length;
}

function decompressedRepresentation(bytes, extension, limit) {
  const options = { maxOutputLength: limit };
  if (extension === ".gz") return gunzipSync(bytes, options);
  if (extension === ".br") return brotliDecompressSync(bytes, options);
  return undefined;
}

async function collectFiles(root, maxFiles, findings) {
  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      if (entry.isSymbolicLink()) {
        findings.push({ severity: "error", rule: "symlink", path: relative, message: "deployment artifact contains a symlink" });
        continue;
      }
      if (entry.isDirectory()) {
        if (SENSITIVE_FILENAMES.has(entry.name.toLowerCase())) {
          findings.push({ severity: "error", rule: "sensitive-directory", path: relative, message: "sensitive development directory is shipped" });
          continue;
        }
        await visit(absolute);
      }
      else if (entry.isFile()) {
        files.push({ absolute, relative });
        if (files.length > maxFiles) throw new Error(`artifact exceeds maxFiles (${maxFiles})`);
      } else {
        findings.push({ severity: "error", rule: "unsupported-file-type", path: relative, message: "deployment artifact contains an unsupported filesystem entry" });
      }
    }
  }
  await visit(root);
  return files;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const artifact = await realpath(args.artifact);
  const artifactStat = await lstat(artifact);
  if (!artifactStat.isDirectory()) throw new Error("artifact must be a directory");
  const requestedReport = path.resolve(args.report);
  await mkdir(path.dirname(requestedReport), { recursive: true });
  const report = path.join(await realpath(path.dirname(requestedReport)), path.basename(requestedReport));
  if (report === artifact || report.startsWith(`${artifact}${path.sep}`)) {
    throw new Error("report must be outside the artifact directory");
  }

  const policy = args.policy
    ? validatePolicy(parsePolicyJson(await readFile(args.policy, "utf8")))
    : validatePolicy({ version: 1 });
  const findings = [];
  const endpoints = new Map();
  const digests = [];
  const files = await collectFiles(artifact, policy.maxFiles, findings);

  if (policy.allowedFiles !== null) {
    const expected = new Set(policy.allowedFiles);
    const actual = new Set(files.map((file) => file.relative));
    for (const relative of [...expected].sort()) {
      if (!actual.has(relative)) findings.push({ severity: "error", rule: "required-file-missing", path: relative, message: "file required by the exact release inventory is missing" });
    }
    for (const relative of [...actual].sort()) {
      if (!expected.has(relative)) findings.push({ severity: "error", rule: "unexpected-release-file", path: relative, message: "file is not present in the exact release inventory" });
    }
  }

  function recordEndpoint(candidate, sourcePath) {
    try {
      const url = new URL(candidate.startsWith("//") ? `https:${candidate}` : candidate);
      const host = url.host.toLowerCase();
      const existing = endpoints.get(host) ?? new Set();
      existing.add(sourcePath);
      endpoints.set(host, existing);
    } catch {
      // The patterns are intentionally permissive; malformed candidates are ignored.
    }
  }

  function scanText(text, sourcePath, representation, decodeBase64 = true, derive = true) {
    if (policy.denySourceMaps && /[#@]\s*sourceMappingURL\s*=/.test(text)) {
      findings.push({ severity: "error", rule: "source-map-reference", path: sourcePath, representation, message: "artifact references a source map" });
    }
    if (policy.denySourceMaps && /["']sourcesContent["']\s*:/.test(text)) {
      findings.push({ severity: "error", rule: "embedded-source-content", path: sourcePath, representation, message: "source map embeds original source content" });
    }

    for (const [rule, pattern] of SECRET_RULES) {
      pattern.lastIndex = 0;
      for (const match of text.matchAll(pattern)) {
        findings.push({
          severity: "error",
          rule,
          path: sourcePath,
          representation,
          line: lineNumber(text, match.index),
          evidence: redactedEvidence(text, match.index, match[0].length),
          message: "credential-like literal is present in a client artifact",
        });
      }
    }

    ASSEMBLED_CREDENTIAL_PATTERN.lastIndex = 0;
    for (const match of text.matchAll(ASSEMBLED_CREDENTIAL_PATTERN)) {
      const assembled = quotedFragments(match[2]).join("");
      if (assembled.length >= 12) {
        findings.push({
          severity: "error",
          rule: "assembled-credential",
          path: sourcePath,
          representation,
          line: lineNumber(text, match.index),
          evidence: `${match[1]}=[REDACTED:${assembled.length}]`,
          message: "credential-like value is assembled from client-side string fragments",
        });
      }
    }

    for (const forbidden of policy.forbiddenSubstrings) {
      let offset = text.indexOf(forbidden);
      while (forbidden && offset !== -1) {
        findings.push({
          severity: "error",
          rule: "policy-forbidden-substring",
          path: sourcePath,
          representation,
          line: lineNumber(text, offset),
          evidence: redactedEvidence(text, offset, forbidden.length),
          message: "policy-forbidden value is present",
        });
        offset = text.indexOf(forbidden, offset + forbidden.length);
      }
    }

    URL_PATTERN.lastIndex = 0;
    for (const match of text.matchAll(URL_PATTERN)) recordEndpoint(match[0], sourcePath);
    PROTOCOL_RELATIVE_PATTERN.lastIndex = 0;
    for (const match of text.matchAll(PROTOCOL_RELATIVE_PATTERN)) recordEndpoint(match[1], sourcePath);

    const unescaped = decodeSimpleEscapes(text);
    if (unescaped !== text) {
      URL_PATTERN.lastIndex = 0;
      for (const match of unescaped.matchAll(URL_PATTERN)) recordEndpoint(match[0], sourcePath);
      PROTOCOL_RELATIVE_PATTERN.lastIndex = 0;
      for (const match of unescaped.matchAll(PROTOCOL_RELATIVE_PATTERN)) recordEndpoint(match[1], sourcePath);
    }

    const percentDecoded = text.replace(/%([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
    if (percentDecoded !== text) scanText(percentDecoded, sourcePath, `${representation}:percent-decoded`, false, false);

    if (derive) {
      CONCATENATED_LITERALS_PATTERN.lastIndex = 0;
      for (const match of text.matchAll(CONCATENATED_LITERALS_PATTERN)) {
        const assembled = quotedFragments(match[0]).join("");
        if (assembled.length > 0) scanText(assembled, sourcePath, `${representation}:concatenation@${match.index}`, false, false);
      }
      ARRAY_JOIN_PATTERN.lastIndex = 0;
      for (const match of text.matchAll(ARRAY_JOIN_PATTERN)) {
        const assembled = quotedFragments(match[1]).join("");
        if (assembled.length > 0) scanText(assembled, sourcePath, `${representation}:array-join@${match.index}`, false, false);
      }
      FROM_CHAR_CODE_PATTERN.lastIndex = 0;
      for (const match of text.matchAll(FROM_CHAR_CODE_PATTERN)) {
        const values = match[1].split(",").map((part) => Number.parseInt(part.trim(), 10));
        if (values.length <= 512 && values.every((value) => Number.isInteger(value) && value >= 0 && value <= 0xffff)) {
          scanText(String.fromCharCode(...values), sourcePath, `${representation}:fromCharCode@${match.index}`, false, false);
        }
      }
      REVERSED_LITERAL_PATTERN.lastIndex = 0;
      for (const match of text.matchAll(REVERSED_LITERAL_PATTERN)) {
        const reversed = decodeSimpleEscapes(match[2]).split("").reverse().join("");
        scanText(reversed, sourcePath, `${representation}:reversed-literal@${match.index}`, false, false);
      }
    }

    if (decodeBase64) {
      let candidates = 0;
      BASE64_PATTERN.lastIndex = 0;
      for (const match of text.matchAll(BASE64_PATTERN)) {
        candidates += 1;
        if (candidates > 128) {
          findings.push({ severity: "error", rule: "base64-candidate-limit", path: sourcePath, representation, message: "too many Base64 candidates to inspect safely" });
          break;
        }
        const decodedBytes = Buffer.from(match[0], "base64");
        if (decodedBytes.length === 0 || decodedBytes.length > policy.maxFileBytes) continue;
        const decoded = decodedBytes.toString("utf8");
        if (printableRatio(decoded) >= 0.8) scanText(decoded, sourcePath, `${representation}:base64@${match.index}`, false, false);
      }
    }
  }

  for (const file of files) {
    const stat = await lstat(file.absolute);
    if (stat.size > policy.maxFileBytes) {
      findings.push({ severity: "error", rule: "file-size-limit", path: file.relative, message: `file exceeds ${policy.maxFileBytes} bytes` });
      continue;
    }
    const bytes = await readFile(file.absolute);
    digests.push({ path: file.relative, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
    const basename = path.basename(file.relative).toLowerCase();
    const extension = path.extname(basename);

    if (SENSITIVE_FILENAMES.has(basename) || basename.startsWith(".env.") || SENSITIVE_EXTENSIONS.has(extension)) {
      findings.push({ severity: "error", rule: "sensitive-file", path: file.relative, message: "sensitive development or credential file is shipped" });
    }
    if (policy.denySourceMaps && (extension === ".map" || basename.endsWith(".map.gz") || basename.endsWith(".map.br"))) {
      findings.push({ severity: "error", rule: "source-map-file", path: file.relative, message: "public source map is shipped" });
    }
    if (policy.denySourceFiles && SOURCE_EXTENSIONS.has(extension)) {
      findings.push({ severity: "error", rule: "source-file", path: file.relative, message: "source-language file is shipped" });
    }
    const looksLikeZip = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && [0x03, 0x05, 0x07].includes(bytes[2]);
    if (ARCHIVE_EXTENSIONS.has(extension) || looksLikeZip) {
      findings.push({ severity: "error", rule: "uninspected-archive", path: file.relative, message: "nested archive requires a matching unpack-and-scan verifier" });
    }

    // Credential and endpoint signatures are ASCII-oriented, so scan every
    // artifact regardless of its extension. This catches disguised payloads.
    scanText(bytes.toString("utf8"), file.relative, "raw");

    if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
      scanText(bytes.subarray(2).toString("utf16le"), file.relative, "utf16le");
    } else if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
      const swapped = Buffer.from(bytes.subarray(2));
      if (swapped.length % 2 !== 0) {
        findings.push({ severity: "error", rule: "malformed-utf16", path: file.relative, message: "UTF-16BE artifact has an odd byte length" });
      } else {
        swapped.swap16();
        scanText(swapped.toString("utf16le"), file.relative, "utf16be");
      }
    } else if (bytes.length >= 8) {
      const sampleLength = Math.min(bytes.length, 4096);
      let evenNulls = 0;
      let oddNulls = 0;
      for (let index = 0; index < sampleLength; index += 1) {
        if (bytes[index] === 0) {
          if (index % 2 === 0) evenNulls += 1;
          else oddNulls += 1;
        }
      }
      const pairs = Math.floor(sampleLength / 2);
      if (oddNulls / pairs > 0.3 && evenNulls / pairs < 0.05) {
        scanText(bytes.subarray(0, bytes.length - (bytes.length % 2)).toString("utf16le"), file.relative, "utf16le-heuristic");
      } else if (evenNulls / pairs > 0.3 && oddNulls / pairs < 0.05) {
        const swapped = Buffer.from(bytes.subarray(0, bytes.length - (bytes.length % 2)));
        swapped.swap16();
        scanText(swapped.toString("utf16le"), file.relative, "utf16be-heuristic");
      }
    }

    const looksLikeGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
    if (extension === ".gz" || extension === ".br" || looksLikeGzip) {
      try {
        const compression = looksLikeGzip ? ".gz" : extension;
        const decompressed = decompressedRepresentation(bytes, compression, policy.maxFileBytes);
        scanText(decompressed.toString("utf8"), file.relative, compression === ".gz" ? "gzip" : "brotli");
      } catch (error) {
        findings.push({
          severity: "error",
          rule: "compressed-content-unreadable",
          path: file.relative,
          message: `compressed artifact could not be inspected within limits: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    }
  }

  if (policy.allowedHosts !== null) {
    const allowed = new Set(policy.allowedHosts.map((host) => host.toLowerCase()));
    for (const [host, sourceFiles] of endpoints) {
      if (!allowed.has(host)) {
        findings.push({
          severity: "error",
          rule: "unapproved-external-host",
          path: [...sourceFiles].sort()[0],
          message: `external host is not approved by policy: ${host}`,
        });
      }
    }
  }
  for (const requiredHost of new Set(policy.requiredHosts.map((host) => host.toLowerCase()))) {
    if (!endpoints.has(requiredHost)) {
      findings.push({
        severity: "error",
        rule: "required-host-not-observed",
        path: ".",
        message: `required external host was not found by static inspection: ${requiredHost}`,
      });
    }
  }

  findings.sort((a, b) => a.path.localeCompare(b.path) || a.rule.localeCompare(b.rule) || (a.line ?? 0) - (b.line ?? 0));
  digests.sort((a, b) => a.path.localeCompare(b.path));
  const artifactSha256 = createHash("sha256")
    .update(digests.map((item) => `${item.path}\0${item.bytes}\0${item.sha256}`).join("\n"))
    .digest("hex");
  const result = {
    schemaVersion: 1,
    artifact,
    generatedAt: new Date().toISOString(),
    status: findings.some((finding) => finding.severity === "error") ? "failed" : "passed",
    assurance: {
      level: "bounded-static",
      limitations: [
        "arbitrary runtime computation and encrypted values are not exhaustively evaluated",
        "runtime configuration, server responses, browser storage, service workers, and network traffic require dynamic verification",
        "the deployed artifact must be matched to artifactSha256",
      ],
    },
    artifactSha256,
    policy,
    summary: {
      filesExamined: digests.length,
      bytesExamined: digests.reduce((total, item) => total + item.bytes, 0),
      errors: findings.filter((finding) => finding.severity === "error").length,
      externalHosts: endpoints.size,
    },
    endpoints: [...endpoints.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([host, sourceFiles]) => ({ host, files: [...sourceFiles].sort() })),
    findings,
    files: digests,
  };

  await writeFile(report, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx" });
  process.stdout.write(`${result.status}: ${result.summary.filesExamined} files, ${result.summary.errors} errors; report ${report}\n`);
  if (result.status !== "passed") process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`verification error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
