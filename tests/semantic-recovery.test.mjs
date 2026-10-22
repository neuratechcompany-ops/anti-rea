import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { normalizeSemanticValue, semanticCandidates, semanticFingerprint } from "../scripts/semantic-recovery.mjs";
const cli = path.resolve(import.meta.dirname, "..", "scripts", "semantic-recovery.mjs");

test("canonicalizes endpoint case, query order, duplicate slashes, and fragments", () => {
  const first = semanticFingerprint("endpoint", "HTTPS://API.EXAMPLE.TEST//v1/decision?b=2&a=1#leak");
  const second = semanticFingerprint("endpoint", "https://api.example.test/v1/decision?a=1&b=2");
  assert.equal(first, second);
});

test("fingerprints JSON structure without retaining primitive values", () => {
  const first = normalizeSemanticValue("json-shape", { decision: { allowed: true, reason: "secret" }, count: 3 });
  const second = normalizeSemanticValue("json-shape", { count: 99, decision: { reason: "different", allowed: false } });
  assert.equal(first, second);
  assert.doesNotMatch(first, /secret|different|99/);
});

test("extracts typed candidates from raw analyzer JSON without trusting analyzer labels", () => {
  const bytes = Buffer.from('{"endpoint":"https://api.example.test/v1/orders?b=2&a=1","symbol":"calculateDiscount"}\n');
  const candidates = semanticCandidates(bytes);
  assert.ok(candidates.some((item) => item.kind === "endpoint" && item.normalizedSha256 === semanticFingerprint("endpoint", "https://api.example.test/v1/orders?a=1&b=2")));
  assert.ok(candidates.some((item) => item.kind === "identifier" && item.normalizedSha256 === semanticFingerprint("identifier", "calculateDiscount")));
});

test("rejects unsupported kinds and credential-bearing endpoints", () => {
  assert.throws(() => semanticFingerprint("regex", "anything"), /unsupported/);
  assert.throws(() => semanticFingerprint("endpoint", "https://user:pass@example.test/x"), /without credentials/);
});

test("fingerprints recovered JavaScript structure across identifier and literal rewriting", () => {
  const owner = "function discount(total, vip) { if (vip && total > 100) return total * 0.8; return total; }";
  const recovered = "function a(x, y) { if (y && x > 999) return x * 0.1; return x; }";
  const changed = "function a(x, y) { if (y || x > 999) return x * 0.1; return x; }";
  assert.equal(semanticFingerprint("js-structure", owner), semanticFingerprint("js-structure", recovered));
  assert.notEqual(semanticFingerprint("js-structure", owner), semanticFingerprint("js-structure", changed));
  assert.ok(semanticCandidates(Buffer.from(recovered)).some((item) => item.kind === "js-structure" && item.normalizedSha256 === semanticFingerprint("js-structure", owner)));
});

test("canonicalizes holdout behavior vectors without exposing inputs or outputs", () => {
  const first = { schemaVersion: 1, cases: [{ inputSha256: "a".repeat(64), outputSha256: "b".repeat(64), status: "returned" }, { inputSha256: "c".repeat(64), outputSha256: "d".repeat(64), status: "threw" }] };
  const reordered = { schemaVersion: 1, cases: structuredClone(first.cases).reverse() };
  assert.equal(semanticFingerprint("behavior-vector", first), semanticFingerprint("behavior-vector", reordered));
  reordered.cases[0].outputSha256 = "e".repeat(64);
  assert.notEqual(semanticFingerprint("behavior-vector", first), semanticFingerprint("behavior-vector", reordered));
  const nested = Buffer.from(JSON.stringify({ recoveredBehavior: first }));
  assert.ok(semanticCandidates(nested).some((item) => item.kind === "behavior-vector" && item.normalizedSha256 === semanticFingerprint("behavior-vector", first)));
});

test("fingerprints WAT structure across symbol, literal, data, and comment rewriting", () => {
  const owner = `(module (func $discount (param $total i32) (result i32)
    ;; owner-only explanation
    local.get $total i32.const 100 i32.gt_s
    (if (result i32) (then i32.const 80) (else i32.const 100)))
    (data (i32.const 0) "owner-secret"))`;
  const recovered = `(module (; nested (; comment ;) ;) (func $a (param $x i32) (result i32)
    local.get $x i32.const 999 i32.gt_s
    (if (result i32) (then i32.const 1) (else i32.const 2)))
    (data (i32.const 44) "different"))`;
  const changed = recovered.replace("i32.gt_s", "i32.lt_s");
  assert.equal(semanticFingerprint("wasm-structure", owner), semanticFingerprint("wasm-structure", recovered));
  assert.notEqual(semanticFingerprint("wasm-structure", owner), semanticFingerprint("wasm-structure", changed));
  const raw = Buffer.from(JSON.stringify({ recoveredWat: recovered }));
  assert.ok(semanticCandidates(raw).some((item) => item.kind === "wasm-structure" && item.normalizedSha256 === semanticFingerprint("wasm-structure", owner)));
});

test("canonicalizes a native CFG across addresses, registers, constants, block IDs, and order", () => {
  const owner = { schemaVersion: 1, architecture: "x86-64", entry: "0x1000", blocks: [
    { id: "0x1000", instructions: [{ mnemonic: "cmp", operandClasses: ["register", "immediate"] }, { mnemonic: "jle", operandClasses: ["relative"] }], successors: ["0x1010", "0x1020"] },
    { id: "0x1010", instructions: [{ mnemonic: "imul", operandClasses: ["register", "immediate"] }, { mnemonic: "ret", operandClasses: [] }], successors: [] },
    { id: "0x1020", instructions: [{ mnemonic: "mov", operandClasses: ["register", "register"] }, { mnemonic: "ret", operandClasses: [] }], successors: [] },
  ] };
  const recovered = { schemaVersion: 1, architecture: "X86-64", entry: "entry", blocks: [
    { id: "fallback", instructions: [{ mnemonic: "mov", operandClasses: ["register", "register"] }, { mnemonic: "ret", operandClasses: [] }], successors: [] },
    { id: "entry", instructions: [{ mnemonic: "cmp", operandClasses: ["register", "immediate"] }, { mnemonic: "jle", operandClasses: ["relative"] }], successors: ["discount", "fallback"] },
    { id: "discount", instructions: [{ mnemonic: "imul", operandClasses: ["register", "immediate"] }, { mnemonic: "ret", operandClasses: [] }], successors: [] },
  ] };
  const changed = structuredClone(recovered); changed.blocks[1].instructions[1].mnemonic = "jg";
  assert.equal(semanticFingerprint("native-cfg", owner), semanticFingerprint("native-cfg", recovered));
  assert.notEqual(semanticFingerprint("native-cfg", owner), semanticFingerprint("native-cfg", changed));
  const raw = Buffer.from(JSON.stringify({ analyzer: { recoveredCfg: recovered } }));
  assert.ok(semanticCandidates(raw).some((item) => item.kind === "native-cfg" && item.normalizedSha256 === semanticFingerprint("native-cfg", owner)));
});

test("rejects malformed native CFGs rather than scoring partial analyzer output", () => {
  const missingSuccessor = { schemaVersion: 1, architecture: "arm64", entry: "a", blocks: [{ id: "a", instructions: [{ mnemonic: "b", operandClasses: ["relative"] }], successors: ["missing"] }] };
  assert.throws(() => semanticFingerprint("native-cfg", missingSuccessor), /successor is unknown/);
  assert.throws(() => semanticFingerprint("wasm-structure", "(module (; unclosed)"), /comment is unbalanced/);
});

test("fingerprints a bounded structure from a file without shell-embedding analyzer output", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-semantic-")); const wat = path.join(directory, "reference.wat");
  await writeFile(wat, "(module (func $x (result i32) i32.const 42))\n");
  const result = spawnSync(process.execPath, [cli, "fingerprint", "--kind", "wasm-structure", "--file", wat], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr); const output = JSON.parse(result.stdout);
  assert.equal(output.kind, "wasm-structure"); assert.match(output.normalizedSha256, /^[a-f0-9]{64}$/);
});
