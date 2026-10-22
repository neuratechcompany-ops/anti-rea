import { createHash } from "node:crypto";

const OPS = new Set(["arithmetic", "branch", "call", "compare", "constant", "convert", "crypto", "input", "load", "merge", "opaque", "output", "return", "store", "table"]);
const VALUE_CLASSES = new Set(["bool", "bytes", "float", "int", "none", "object", "pointer", "string", "unknown"]);
const CONTROL_KINDS = new Set(["case", "exception", "false", "fallthrough", "return", "true"]);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
};
const identifier = (value, label) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(value)) throw new Error(`${label} is invalid`);
  return value;
};

export function canonicalizeSemanticIr(value) {
  exactKeys(value, ["controlEdges", "dataEdges", "entry", "nodes", "schemaVersion"], "semantic IR");
  if (value.schemaVersion !== 1 || !Array.isArray(value.nodes) || value.nodes.length < 2 || value.nodes.length > 4096) throw new Error("semantic IR node inventory is invalid");
  if (!Array.isArray(value.controlEdges) || !Array.isArray(value.dataEdges) || value.controlEdges.length + value.dataEdges.length > 16384) throw new Error("semantic IR edge inventory is invalid");
  const nodes = new Map();
  for (const [index, node] of value.nodes.entries()) {
    exactKeys(node, ["id", "op", "valueClass"], `semantic IR nodes[${index}]`); const id = identifier(node.id, `semantic IR nodes[${index}].id`);
    if (nodes.has(id) || !OPS.has(node.op) || !VALUE_CLASSES.has(node.valueClass)) throw new Error(`semantic IR nodes[${index}] is invalid or duplicate`);
    nodes.set(id, { id, op: node.op, valueClass: node.valueClass, incoming: [], outgoing: [] });
  }
  const entry = identifier(value.entry, "semantic IR entry"); if (!nodes.has(entry)) throw new Error("semantic IR entry is missing");
  const edges = [];
  for (const [index, edge] of value.controlEdges.entries()) {
    exactKeys(edge, ["from", "kind", "to"], `semantic IR controlEdges[${index}]`); const from = identifier(edge.from, `semantic IR controlEdges[${index}].from`); const to = identifier(edge.to, `semantic IR controlEdges[${index}].to`);
    if (!nodes.has(from) || !nodes.has(to) || !CONTROL_KINDS.has(edge.kind)) throw new Error(`semantic IR controlEdges[${index}] is invalid`);
    edges.push({ from, to, kind: `c:${edge.kind}` });
  }
  for (const [index, edge] of value.dataEdges.entries()) {
    exactKeys(edge, ["from", "input", "to"], `semantic IR dataEdges[${index}]`); const from = identifier(edge.from, `semantic IR dataEdges[${index}].from`); const to = identifier(edge.to, `semantic IR dataEdges[${index}].to`);
    if (!nodes.has(from) || !nodes.has(to) || !Number.isSafeInteger(edge.input) || edge.input < 0 || edge.input > 255) throw new Error(`semantic IR dataEdges[${index}] is invalid`);
    edges.push({ from, to, kind: `d:${edge.input}` });
  }
  const edgeIdentities = new Set();
  for (const edge of edges) {
    const identity = `${edge.from}\0${edge.kind}\0${edge.to}`; if (edgeIdentities.has(identity)) throw new Error("semantic IR contains duplicate edges"); edgeIdentities.add(identity);
    nodes.get(edge.from).outgoing.push(edge); nodes.get(edge.to).incoming.push(edge);
  }
  const visited = new Set([entry]); const queue = [entry];
  while (queue.length > 0) { const id = queue.shift(); for (const edge of nodes.get(id).outgoing) if (!visited.has(edge.to)) { visited.add(edge.to); queue.push(edge.to); } }
  if (visited.size !== nodes.size) throw new Error("semantic IR contains nodes unreachable from entry");
  if (![...nodes.values()].some((node) => node.op === "return" || node.op === "output")) throw new Error("semantic IR has no observable exit");
  if ([...nodes.values()].filter((node) => node.op === "opaque").length / nodes.size > 0.2) throw new Error("semantic IR contains too many opaque operations");
  let labels = new Map([...nodes].map(([id, node]) => [id, sha256(Buffer.from(`${node.op}\0${node.valueClass}\0${node.incoming.map((edge) => edge.kind).sort().join(",")}\0${node.outgoing.map((edge) => edge.kind).sort().join(",")}`))]));
  for (let round = 0; round < 16; round += 1) {
    const next = new Map();
    for (const [id, node] of nodes) {
      const incoming = node.incoming.map((edge) => `${edge.kind}:${labels.get(edge.from)}`).sort(); const outgoing = node.outgoing.map((edge) => `${edge.kind}:${labels.get(edge.to)}`).sort();
      next.set(id, sha256(Buffer.from(`${labels.get(id)}\0${incoming.join("|")}\0${outgoing.join("|")}`)));
    }
    labels = next;
  }
  const nodeFeatures = [...labels.values()].map((label) => `n:${label}`);
  const edgeFeatures = edges.map((edge) => `e:${edge.kind}:${labels.get(edge.from)}:${labels.get(edge.to)}`);
  const features = [...new Set([...nodeFeatures, ...edgeFeatures])].sort();
  const canonical = { entry: labels.get(entry), nodes: nodeFeatures.sort(), edges: edgeFeatures.sort() };
  return { fingerprint: sha256(Buffer.from(JSON.stringify(canonical))), features, featureSetSha256: sha256(Buffer.from(features.join("\n"))), nodeCount: nodes.size, edgeCount: edges.length };
}
