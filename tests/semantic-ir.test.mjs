import assert from "node:assert/strict";
import test from "node:test";
import { canonicalizeSemanticIr } from "../scripts/semantic-ir.mjs";

function graph(ids = ["arg", "limit", "cmp", "branch", "allow", "deny", "exit"]) {
  const [arg, limit, cmp, branch, allow, deny, exit] = ids;
  return {
    schemaVersion: 1, entry: arg,
    nodes: [
      { id: arg, op: "input", valueClass: "int" }, { id: limit, op: "constant", valueClass: "int" },
      { id: cmp, op: "compare", valueClass: "bool" }, { id: branch, op: "branch", valueClass: "none" },
      { id: allow, op: "constant", valueClass: "string" }, { id: deny, op: "constant", valueClass: "string" },
      { id: exit, op: "return", valueClass: "string" },
    ],
    controlEdges: [
      { from: arg, to: limit, kind: "fallthrough" }, { from: limit, to: cmp, kind: "fallthrough" }, { from: cmp, to: branch, kind: "fallthrough" },
      { from: branch, to: allow, kind: "true" }, { from: branch, to: deny, kind: "false" }, { from: allow, to: exit, kind: "return" }, { from: deny, to: exit, kind: "return" },
    ],
    dataEdges: [{ from: arg, to: cmp, input: 0 }, { from: limit, to: cmp, input: 1 }, { from: cmp, to: branch, input: 0 }, { from: allow, to: exit, input: 0 }, { from: deny, to: exit, input: 0 }],
  };
}

test("semantic IR fingerprint ignores node identifiers and inventory order", () => {
  const left = graph(); const right = graph(["n6", "n2", "n9", "n1", "n8", "n3", "n4"]);
  right.nodes.reverse(); right.controlEdges.reverse(); right.dataEdges.reverse();
  const a = canonicalizeSemanticIr(left); const b = canonicalizeSemanticIr(right);
  assert.equal(a.fingerprint, b.fingerprint); assert.deepEqual(a.features, b.features);
});

test("semantic IR fingerprint distinguishes changed operations", () => {
  const left = graph(); const right = graph(); right.nodes.find((node) => node.id === "cmp").op = "arithmetic";
  assert.notEqual(canonicalizeSemanticIr(left).fingerprint, canonicalizeSemanticIr(right).fingerprint);
});

test("semantic IR rejects unreachable, duplicate, and opaque-heavy partial graphs", () => {
  const unreachable = graph(); unreachable.nodes.push({ id: "lost", op: "load", valueClass: "bytes" }); assert.throws(() => canonicalizeSemanticIr(unreachable), /unreachable/);
  const duplicate = graph(); duplicate.controlEdges.push({ ...duplicate.controlEdges[0] }); assert.throws(() => canonicalizeSemanticIr(duplicate), /duplicate edges/);
  const opaque = graph(); for (const node of opaque.nodes) if (node.op !== "return") node.op = "opaque"; assert.throws(() => canonicalizeSemanticIr(opaque), /too many opaque/);
});
