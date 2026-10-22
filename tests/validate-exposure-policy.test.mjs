import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const validator = path.join(root, "scripts", "validate-exposure-policy.mjs");
function sha(value) { return createHash("sha256").update(value).digest("hex"); }

async function run(fact, artifactText = "console.log('safe')") {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-exposure-"));
  const artifact = path.join(directory, "artifact"); await mkdir(artifact);
  const bytes = Buffer.from(artifactText); await writeFile(path.join(artifact, "app.js"), bytes);
  const artifactSha256 = sha(Buffer.from(`app.js\0${bytes.length}\0${sha(bytes)}`));
  const artifactReport = path.join(directory, "artifact.json");
  await writeFile(artifactReport, JSON.stringify({ schemaVersion: 1, status: "passed", artifact, artifactSha256 }));
  const policy = path.join(directory, "policy.json"); await writeFile(policy, JSON.stringify({ schemaVersion: 2, facts: [fact] }));
  const report = path.join(directory, "result.json");
  const result = spawnSync(process.execPath, [validator, "--policy", policy, "--artifact-report", artifactReport, "--report", report], { encoding: "utf8" });
  return { result, report };
}

const serverFact = {
  id: "AUTH-01", description: "final entitlement", classification: "SERVER_REQUIRED", impact: "authorization",
  tiers: ["T0", "T1", "T2", "T3"], authoritativeLocation: "server", clientImplementation: false,
  serverAuthoritative: true, canaries: ["anti-rea-test-entitlement-authority"], recoverySignals: [],
};

test("accepts a server-required fact absent from the verified client", async () => {
  const { result } = await run(serverFact);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, "PASS");
});

test("rejects high-impact logic classified as client cost-only", async () => {
  const fact = { ...serverFact, classification: "COST_ONLY", authoritativeLocation: "client", clientImplementation: true };
  const { result } = await run(fact);
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stdout, /high-impact-not-server-required/);
});

test("rejects a server-only canary shipped raw or base64", async () => {
  for (const value of [serverFact.canaries[0], Buffer.from(serverFact.canaries[0]).toString("base64")]) {
    const { result } = await run(serverFact, `const leaked = ${JSON.stringify(value)};`);
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stdout, /server-required-canary-in-client/);
  }
});

test("rejects contradictory client authority claimed as server-authoritative", async () => {
  const fact = {
    ...serverFact,
    id: "COMM-01",
    classification: "COST_ONLY",
    impact: "commercial",
    authoritativeLocation: "client",
    clientImplementation: true,
    serverAuthoritative: true,
  };
  const { result } = await run(fact);
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stdout, /server-authoritative-location-contradiction/);
});

test("requires typed semantic recovery signals for client cost-only facts", async () => {
  const fact = { ...serverFact, id: "UI-01", classification: "COST_ONLY", impact: "none", authoritativeLocation: "client", clientImplementation: true, serverAuthoritative: false };
  const { result } = await run(fact);
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stdout, /cost-only-missing-semantic-recovery-signal/);
});
