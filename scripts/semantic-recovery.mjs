#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import process from "node:process";
import { parse } from "acorn";

export const SEMANTIC_SIGNAL_SCORES = Object.freeze({
  "exact-text": 4,
  endpoint: 3,
  "json-shape": 3,
  identifier: 2,
  "js-structure": 4,
  "behavior-vector": 4,
  "wasm-structure": 4,
  "native-cfg": 4,
});

const MAX_TEXT_BYTES = 16 * 1024 * 1024;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_CANDIDATES = 50_000;
const MAX_DEPTH = 32;
const MAX_CODE_BYTES = 256 * 1024;
const MAX_AST_NODES = 100_000;
const MAX_CFG_BLOCKS = 4096;
const MAX_CFG_INSTRUCTIONS = 100_000;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function normalizedText(value) {
  if (typeof value !== "string") throw new Error("semantic value must be a string");
  const normalized = value.normalize("NFKC").trim().replace(/\s+/gu, " ");
  if (!normalized || normalized.length > 4096 || /[\u0000]/u.test(normalized)) throw new Error("semantic text is empty or too large");
  return normalized;
}

function jsonShape(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error("json shape exceeds depth limit");
  if (value === null) return null;
  if (Array.isArray(value)) {
    const shapes = [...new Set(value.slice(0, 1024).map((item) => JSON.stringify(jsonShape(item, depth + 1))))].sort();
    return { array: shapes.map((item) => JSON.parse(item)) };
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    if (keys.length > 1024) throw new Error("json shape has too many keys");
    return Object.fromEntries(keys.map((key) => [key, jsonShape(value[key], depth + 1)]));
  }
  return typeof value;
}

function jsStructure(value) {
  if (typeof value !== "string" || !value.trim() || Buffer.byteLength(value) > MAX_CODE_BYTES) throw new Error("JavaScript semantic value is empty or too large");
  const ast = parse(value, { ecmaVersion: "latest", sourceType: "module", allowHashBang: true });
  let nodes = 0;
  function shape(current, depth = 0, key = "") {
    if (depth > 256 || ++nodes > MAX_AST_NODES) throw new Error("JavaScript structure exceeds limits");
    if (current === null || typeof current !== "object") {
      if (key === "operator" || key === "kind" || key === "method" || key === "computed" || key === "optional" || key === "async" || key === "generator") return current;
      return typeof current;
    }
    if (Array.isArray(current)) return current.map((item) => shape(item, depth + 1));
    const result = { type: current.type ?? "Object" };
    for (const name of Object.keys(current).sort()) {
      if (new Set(["type", "start", "end", "loc", "range", "raw", "name", "value", "regex", "bigint"]).has(name)) continue;
      result[name] = shape(current[name], depth + 1, name);
    }
    return result;
  }
  return JSON.stringify(shape(ast));
}

function behaviorVector(value) {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).sort().join("\0") !== "cases\0schemaVersion" || parsed.schemaVersion !== 1 || !Array.isArray(parsed.cases) || parsed.cases.length === 0 || parsed.cases.length > 256) throw new Error("behavior vector is invalid");
  const cases = parsed.cases.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item) || Object.keys(item).sort().join("\0") !== "inputSha256\0outputSha256\0status" || !/^[a-f0-9]{64}$/.test(item.inputSha256 ?? "") || !/^[a-f0-9]{64}$/.test(item.outputSha256 ?? "") || !new Set(["returned", "threw"]).has(item.status)) throw new Error("behavior vector case is invalid");
    return { inputSha256: item.inputSha256, outputSha256: item.outputSha256, status: item.status };
  }).sort((left, right) => left.inputSha256.localeCompare(right.inputSha256));
  if (new Set(cases.map((item) => item.inputSha256)).size !== cases.length) throw new Error("behavior vector inputs must be unique");
  return JSON.stringify({ schemaVersion: 1, cases });
}

function watStructure(value) {
  if (typeof value !== "string" || !value.trim() || Buffer.byteLength(value) > MAX_CODE_BYTES) throw new Error("WAT semantic value is empty or too large");
  const tokens = [];
  for (let index = 0; index < value.length;) {
    if (/\s/u.test(value[index])) { index += 1; continue; }
    if (value.startsWith(";;", index)) { index = value.indexOf("\n", index + 2); if (index === -1) index = value.length; continue; }
    if (value.startsWith("(;", index)) {
      let commentDepth = 1; index += 2;
      while (index < value.length && commentDepth > 0) {
        if (value.startsWith("(;", index)) { commentDepth += 1; index += 2; }
        else if (value.startsWith(";)", index)) { commentDepth -= 1; index += 2; }
        else index += 1;
      }
      if (commentDepth !== 0) throw new Error("WAT block comment is unbalanced");
      continue;
    }
    if (value[index] === "(" || value[index] === ")") { tokens.push(value[index]); index += 1; continue; }
    if (value[index] === '"') {
      let cursor = index + 1; let escaped = false;
      for (; cursor < value.length; cursor += 1) {
        if (escaped) escaped = false;
        else if (value[cursor] === "\\") escaped = true;
        else if (value[cursor] === '"') break;
      }
      if (cursor >= value.length) throw new Error("WAT string is unbalanced");
      tokens.push(value.slice(index, cursor + 1)); index = cursor + 1; continue;
    }
    let cursor = index + 1;
    while (cursor < value.length && !/\s|[()]/u.test(value[cursor])) cursor += 1;
    tokens.push(value.slice(index, cursor)); index = cursor;
  }
  if (tokens.length < 3 || tokens.length > MAX_AST_NODES || tokens[0] !== "(" || !tokens.includes("module")) throw new Error("WAT structure is invalid");
  let depth = 0;
  const normalized = tokens.map((token) => {
    if (token === "(") { depth += 1; if (depth > 256) throw new Error("WAT structure exceeds depth limit"); return token; }
    if (token === ")") { depth -= 1; if (depth < 0) throw new Error("WAT structure is unbalanced"); return token; }
    if (token.startsWith("$")) return "$id";
    if (token.startsWith('"')) return '"str"';
    if (/^[+-]?(?:0x[0-9a-f](?:_?[0-9a-f])*|\d(?:_?\d)*(?:\.\d(?:_?\d)*)?(?:e[+-]?\d+)?)(?::[a-z0-9_]+)?$/iu.test(token)) return "#";
    return token.toLowerCase();
  });
  if (depth !== 0) throw new Error("WAT structure is unbalanced");
  return normalized.join(" ");
}

function nativeCfg(value) {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).sort().join("\0") !== "architecture\0blocks\0entry\0schemaVersion" || parsed.schemaVersion !== 1 || typeof parsed.architecture !== "string" || !/^[a-z0-9][a-z0-9_.-]{1,31}$/i.test(parsed.architecture) || !Array.isArray(parsed.blocks) || parsed.blocks.length === 0 || parsed.blocks.length > MAX_CFG_BLOCKS || typeof parsed.entry !== "string") throw new Error("native CFG is invalid");
  const blocks = new Map(); let instructionCount = 0;
  const operandKinds = new Set(["register", "immediate", "memory", "relative", "stack", "symbol", "other"]);
  for (const [index, block] of parsed.blocks.entries()) {
    if (!block || typeof block !== "object" || Array.isArray(block) || Object.keys(block).sort().join("\0") !== "id\0instructions\0successors" || typeof block.id !== "string" || !/^[A-Za-z0-9_.:@+-]{1,128}$/.test(block.id) || blocks.has(block.id) || !Array.isArray(block.instructions) || block.instructions.length === 0 || !Array.isArray(block.successors) || block.successors.length > 32 || new Set(block.successors).size !== block.successors.length || block.successors.some((item) => typeof item !== "string")) throw new Error(`native CFG block ${index} is invalid`);
    const instructions = block.instructions.map((instruction, instructionIndex) => {
      instructionCount += 1;
      if (instructionCount > MAX_CFG_INSTRUCTIONS || !instruction || typeof instruction !== "object" || Array.isArray(instruction) || Object.keys(instruction).sort().join("\0") !== "mnemonic\0operandClasses" || typeof instruction.mnemonic !== "string" || !/^[a-z][a-z0-9_.]{0,31}$/i.test(instruction.mnemonic) || !Array.isArray(instruction.operandClasses) || instruction.operandClasses.length > 16 || instruction.operandClasses.some((item) => !operandKinds.has(item))) throw new Error(`native CFG instruction ${index}:${instructionIndex} is invalid`);
      return `${instruction.mnemonic.toLowerCase()}(${instruction.operandClasses.join(",")})`;
    });
    blocks.set(block.id, { instructions, successors: block.successors });
  }
  if (!blocks.has(parsed.entry)) throw new Error("native CFG entry is unknown");
  for (const block of blocks.values()) for (const successor of block.successors) if (!blocks.has(successor)) throw new Error("native CFG successor is unknown");
  const predecessors = new Map([...blocks.keys()].map((id) => [id, []]));
  for (const [id, block] of blocks) for (const successor of block.successors) predecessors.get(successor).push(id);
  let labels = new Map([...blocks].map(([id, block]) => [id, sha256(Buffer.from(`${id === parsed.entry ? "entry" : "block"}\0${block.instructions.join(";")}\0out:${block.successors.length}\0in:${predecessors.get(id).length}`))]));
  const rounds = Math.min(32, blocks.size + 1);
  for (let round = 0; round < rounds; round += 1) {
    labels = new Map([...blocks].map(([id, block]) => [id, sha256(Buffer.from(`${labels.get(id)}\0p:${predecessors.get(id).map((item) => labels.get(item)).sort().join(",")}\0s:${block.successors.map((item) => labels.get(item)).sort().join(",")}`))]));
  }
  const nodes = [...labels.values()].sort();
  const edges = [...blocks].flatMap(([id, block]) => block.successors.map((successor) => `${labels.get(id)}>${labels.get(successor)}`)).sort();
  return JSON.stringify({ schemaVersion: 1, architecture: parsed.architecture.toLowerCase(), entry: labels.get(parsed.entry), nodes, edges });
}

export function normalizeSemanticValue(kind, value) {
  if (!(kind in SEMANTIC_SIGNAL_SCORES)) throw new Error(`unsupported semantic signal kind: ${kind}`);
  if (kind === "exact-text") return normalizedText(value);
  if (kind === "js-structure") return jsStructure(value);
  if (kind === "behavior-vector") return behaviorVector(value);
  if (kind === "wasm-structure") return watStructure(value);
  if (kind === "native-cfg") return nativeCfg(value);
  if (kind === "identifier") {
    const normalized = normalizedText(value);
    if (!/^[\p{L}_$][\p{L}\p{N}_$.-]{1,255}$/u.test(normalized)) throw new Error("semantic identifier is invalid");
    return normalized;
  }
  if (kind === "endpoint") {
    const url = new URL(normalizedText(value));
    if (!new Set(["http:", "https:"]).has(url.protocol) || url.username || url.password) throw new Error("semantic endpoint must be an HTTP(S) URL without credentials");
    url.hash = "";
    url.pathname = url.pathname.replace(/\/{2,}/g, "/");
    const sorted = [...url.searchParams.entries()].sort(([aKey, aValue], [bKey, bValue]) => aKey.localeCompare(bKey) || aValue.localeCompare(bValue));
    url.search = "";
    for (const [key, item] of sorted) url.searchParams.append(key, item);
    return url.href;
  }
  let parsed = value;
  if (typeof value === "string") parsed = JSON.parse(value);
  return JSON.stringify(jsonShape(parsed));
}

export function semanticFingerprint(kind, value) {
  return sha256(Buffer.from(normalizeSemanticValue(kind, value)));
}

function addCandidate(store, kind, value) {
  if (store.length >= MAX_CANDIDATES) return;
  try { store.push({ kind, normalizedSha256: semanticFingerprint(kind, value) }); } catch {}
}

function walkJson(value, store, depth = 0) {
  if (depth > MAX_DEPTH || store.length >= MAX_CANDIDATES) return;
  if (typeof value === "string") {
    addCandidate(store, "exact-text", value);
    addCandidate(store, "identifier", value);
    addCandidate(store, "endpoint", value);
    if (value.length <= 32 * 1024 && /(?:=>|[;{}=]|\b(?:function|if|return|switch)\b)/u.test(value)) addCandidate(store, "js-structure", value);
    if (value.length <= MAX_CODE_BYTES && /\(\s*module\b/u.test(value)) addCandidate(store, "wasm-structure", value);
    return;
  }
  if (!value || typeof value !== "object") return;
  addCandidate(store, "json-shape", value);
  addCandidate(store, "behavior-vector", value);
  addCandidate(store, "native-cfg", value);
  if (Array.isArray(value)) for (const item of value.slice(0, 1024)) walkJson(item, store, depth + 1);
  else for (const key of Object.keys(value).sort().slice(0, 1024)) walkJson(value[key], store, depth + 1);
}

export function semanticCandidates(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_TEXT_BYTES) return [];
  const text = bytes.toString("utf8");
  const candidates = [];
  if (bytes.length <= MAX_CODE_BYTES) addCandidate(candidates, "js-structure", text);
  if (bytes.length <= MAX_CODE_BYTES) addCandidate(candidates, "wasm-structure", text);
  for (const match of text.matchAll(/```(?:javascript|js)?\s*\n([\s\S]{1,262144}?)```/giu)) addCandidate(candidates, "js-structure", match[1]);
  for (const match of text.matchAll(/```(?:wat|wasm)?\s*\n([\s\S]{1,262144}?)```/giu)) addCandidate(candidates, "wasm-structure", match[1]);
  for (const line of text.split(/\r?\n/u).slice(0, MAX_CANDIDATES)) if (line.trim().length <= 4096) addCandidate(candidates, "exact-text", line);
  for (const match of text.matchAll(/https?:\/\/[^\s"'<>\\]{1,2048}/giu)) addCandidate(candidates, "endpoint", match[0].replace(/[),.;]+$/u, ""));
  for (const match of text.matchAll(/(?<![\p{L}\p{N}_$.-])[\p{L}_$][\p{L}\p{N}_$.-]{1,255}(?![\p{L}\p{N}_$.-])/gu)) addCandidate(candidates, "identifier", match[0]);
  if (bytes.length <= MAX_JSON_BYTES) {
    try { walkJson(JSON.parse(text), candidates); } catch {}
  }
  const unique = new Map(candidates.map((item) => [`${item.kind}:${item.normalizedSha256}`, item]));
  return [...unique.values()];
}

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: semantic-recovery.mjs fingerprint --kind KIND (--value VALUE | --file FILE)\n");
  process.exit(64);
}

async function main() {
  const [mode, ...argv] = process.argv.slice(2);
  if (mode !== "fingerprint") usage("mode must be fingerprint");
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || options[key.slice(2)] !== undefined) usage("invalid arguments");
    options[key.slice(2)] = value;
  }
  if (!options.kind || (options.value === undefined) === (options.file === undefined) || Object.keys(options).some((key) => !new Set(["file", "kind", "value"]).has(key))) usage("--kind and exactly one of --value or --file are required");
  const value = options.file === undefined ? options.value : await readFile(options.file, "utf8");
  process.stdout.write(`${JSON.stringify({ kind: options.kind, normalized: normalizeSemanticValue(options.kind, value), normalizedSha256: semanticFingerprint(options.kind, value), score: SEMANTIC_SIGNAL_SCORES[options.kind] }, null, 2)}\n`);
}

if (process.argv[1]?.endsWith("semantic-recovery.mjs")) main().catch((error) => { process.stderr.write(`semantic recovery error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
