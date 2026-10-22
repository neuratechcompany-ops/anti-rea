#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstat, open, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { SEMANTIC_SIGNAL_SCORES } from "./semantic-recovery.mjs";

const CLASSIFICATIONS = new Set(["PUBLIC", "COST_ONLY", "SERVER_REQUIRED"]);
const IMPACTS = new Set(["none", "commercial", "financial", "authorization", "security"]);
const TIERS = new Set(["T0", "T1", "T2", "T3"]);
const HIGH_IMPACTS = new Set(["financial", "authorization", "security"]);

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: validate-exposure-policy.mjs --policy POLICY.json --artifact-report VERIFICATION.json --report NEW.json\n");
  process.exit(64);
}

function args(argv) {
  const value = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const item = argv[index + 1];
    if (!key?.startsWith("--") || item === undefined) usage("invalid arguments");
    value[key.slice(2)] = item;
  }
  for (const name of ["policy", "artifact-report", "report"]) if (!value[name]) usage(`--${name} is required`);
  return value;
}

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("|") !== [...keys].sort().join("|")) throw new Error(`${label} has invalid fields`);
}

async function inventory(rootValue) {
  const root = await realpath(rootValue);
  if (!(await lstat(root)).isDirectory()) throw new Error("artifact must be a directory");
  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      if (entry.isSymbolicLink()) throw new Error(`artifact contains symlink: ${relative}`);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile()) {
        const bytes = await readFile(absolute);
        files.push({ path: relative, bytes });
      } else throw new Error(`artifact contains unsupported entry: ${relative}`);
    }
  }
  await visit(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  const digestRows = files.map((file) => `${file.path}\0${file.bytes.length}\0${sha256(file.bytes)}`).join("\n");
  return { root, files, sha256: sha256(Buffer.from(digestRows)) };
}

async function main() {
  const options = args(process.argv.slice(2));
  const policyBytes = await readFile(options.policy);
  const policy = JSON.parse(policyBytes.toString("utf8"));
  exactKeys(policy, ["facts", "schemaVersion"], "policy");
  if (policy.schemaVersion !== 2 || !Array.isArray(policy.facts) || policy.facts.length === 0) throw new Error("policy requires schemaVersion 2 and nonempty facts");
  const artifactReportBytes = await readFile(options["artifact-report"]);
  const artifactReport = JSON.parse(artifactReportBytes.toString("utf8"));
  if (artifactReport?.schemaVersion !== 1 || artifactReport?.status !== "passed" || !/^[a-f0-9]{64}$/.test(artifactReport?.artifactSha256 ?? "")) throw new Error("artifact report is not a passed verification");
  const artifact = await inventory(artifactReport.artifact);
  if (artifact.sha256 !== artifactReport.artifactSha256) throw new Error("artifact changed after verification");

  const ids = new Set();
  const findings = [];
  for (const [index, fact] of policy.facts.entries()) {
    const label = `facts[${index}]`;
    exactKeys(fact, ["authoritativeLocation", "canaries", "classification", "clientImplementation", "description", "id", "impact", "recoverySignals", "serverAuthoritative", "tiers"], label);
    if (typeof fact.id !== "string" || !/^[A-Z][A-Z0-9-]{1,63}$/.test(fact.id) || ids.has(fact.id)) throw new Error(`${label}.id is invalid or duplicate`);
    ids.add(fact.id);
    if (typeof fact.description !== "string" || !fact.description.trim()) throw new Error(`${label}.description is required`);
    if (!CLASSIFICATIONS.has(fact.classification) || !IMPACTS.has(fact.impact)) throw new Error(`${label} has invalid classification or impact`);
    if (!new Set(["client", "server"]).has(fact.authoritativeLocation) || typeof fact.clientImplementation !== "boolean" || typeof fact.serverAuthoritative !== "boolean") throw new Error(`${label} has invalid placement fields`);
    if (!Array.isArray(fact.tiers) || fact.tiers.length === 0 || fact.tiers.some((tier) => !TIERS.has(tier)) || new Set(fact.tiers).size !== fact.tiers.length) throw new Error(`${label}.tiers is invalid`);
    if (!Array.isArray(fact.canaries) || fact.canaries.some((item) => typeof item !== "string" || item.length < 4 || item.length > 1024)) throw new Error(`${label}.canaries is invalid`);
    if (!Array.isArray(fact.recoverySignals)) throw new Error(`${label}.recoverySignals is invalid`);
    const signalIds = new Set();
    for (const [signalIndex, signal] of fact.recoverySignals.entries()) {
      exactKeys(signal, ["id", "kind", "normalizedSha256"], `${label}.recoverySignals[${signalIndex}]`);
      if (typeof signal.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(signal.id) || signalIds.has(signal.id)) throw new Error(`${label}.recoverySignals[${signalIndex}].id is invalid or duplicate`);
      signalIds.add(signal.id);
      if (!(signal.kind in SEMANTIC_SIGNAL_SCORES) || typeof signal.normalizedSha256 !== "string" || !/^[a-f0-9]{64}$/.test(signal.normalizedSha256)) throw new Error(`${label}.recoverySignals[${signalIndex}] is invalid`);
    }
    if (fact.classification === "COST_ONLY" && fact.clientImplementation && fact.recoverySignals.length === 0) findings.push({ severity: "error", fact: fact.id, rule: "cost-only-missing-semantic-recovery-signal" });

    if (HIGH_IMPACTS.has(fact.impact) && fact.classification !== "SERVER_REQUIRED") findings.push({ severity: "error", fact: fact.id, rule: "high-impact-not-server-required" });
    if (fact.classification === "SERVER_REQUIRED") {
      if (fact.authoritativeLocation !== "server") findings.push({ severity: "error", fact: fact.id, rule: "server-required-authority-in-client" });
      if (fact.clientImplementation) findings.push({ severity: "error", fact: fact.id, rule: "server-required-client-implementation" });
      if (!fact.serverAuthoritative) findings.push({ severity: "error", fact: fact.id, rule: "server-required-not-authoritative" });
      if (fact.canaries.length === 0) findings.push({ severity: "error", fact: fact.id, rule: "server-required-missing-negative-canary" });
    }
    if (fact.serverAuthoritative && fact.authoritativeLocation !== "server") findings.push({ severity: "error", fact: fact.id, rule: "server-authoritative-location-contradiction" });
    if (fact.impact !== "none" && !fact.serverAuthoritative) findings.push({ severity: "error", fact: fact.id, rule: "impactful-client-is-authoritative" });

    if (fact.classification === "SERVER_REQUIRED") {
      for (const canary of fact.canaries) {
        const raw = Buffer.from(canary);
        const base64 = Buffer.from(canary).toString("base64");
        const matches = artifact.files.filter((file) => file.bytes.includes(raw) || file.bytes.includes(Buffer.from(base64)));
        for (const file of matches) findings.push({ severity: "error", fact: fact.id, rule: "server-required-canary-in-client", path: file.path, canarySha256: sha256(raw) });
      }
    }
  }
  findings.sort((a, b) => a.fact.localeCompare(b.fact) || a.rule.localeCompare(b.rule) || (a.path ?? "").localeCompare(b.path ?? ""));
  const result = {
    schemaVersion: 1,
    status: findings.some((item) => item.severity === "error") ? "FAIL" : "PASS",
    policy: { path: path.resolve(options.policy), sha256: sha256(policyBytes), facts: policy.facts.length },
    artifactVerification: { path: path.resolve(options["artifact-report"]), sha256: sha256(artifactReportBytes), artifactSha256: artifact.sha256 },
    assurance: "declared-trust-boundary-plus-static-canary",
    limitations: ["the policy declaration requires independent architecture review", "typed semantic matching covers only owner-precommitted normalizers and is not exhaustive semantic proof"],
    findings,
  };
  const handle = await open(path.resolve(options.report), "wx", 0o644);
  try { await handle.writeFile(`${JSON.stringify(result, null, 2)}\n`); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.status === "FAIL") process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`exposure policy error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
