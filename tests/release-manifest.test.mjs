import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const cli = path.join(root, "scripts", "release-manifest.mjs");

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-manifest-"));
  const release = path.join(directory, "release");
  await mkdir(release);
  await writeFile(path.join(release, "app.js"), "console.log('release')");
  const pair = generateKeyPairSync("ed25519");
  const privateKey = path.join(directory, "private.pem");
  const publicKey = path.join(directory, "public.pem");
  await writeFile(privateKey, pair.privateKey.export({ type: "pkcs8", format: "pem" }));
  await writeFile(publicKey, pair.publicKey.export({ type: "spki", format: "pem" }));
  return { directory, release, privateKey, publicKey, manifest: path.join(directory, "release.manifest.json") };
}

function create(current) {
  return spawnSync(process.execPath, [cli, "create", "--root", current.release, "--private-key", current.privateKey, "--product", "demo", "--release", "1.0.0", "--out", current.manifest], { encoding: "utf8" });
}

function verify(current, publicKey = current.publicKey) {
  return spawnSync(process.execPath, [cli, "verify", "--root", current.release, "--public-key", publicKey, "--product", "demo", "--release", "1.0.0", "--manifest", current.manifest], { encoding: "utf8" });
}

test("signs and verifies the exact release inventory", async () => {
  const current = await fixture();
  assert.equal(create(current).status, 0);
  const result = verify(current);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, "verified");
});

test("rejects modified, missing, and extra release files", async () => {
  for (const mutation of ["modified", "missing", "extra"]) {
    const current = await fixture();
    assert.equal(create(current).status, 0);
    if (mutation === "modified") await writeFile(path.join(current.release, "app.js"), "changed");
    if (mutation === "missing") {
      const { unlink } = await import("node:fs/promises");
      await unlink(path.join(current.release, "app.js"));
    }
    if (mutation === "extra") await writeFile(path.join(current.release, "debug.map"), "extra");
    const result = verify(current);
    assert.equal(result.status, 2, `${mutation}: ${result.stderr}`);
    assert.ok(JSON.parse(result.stdout).findings.some((finding) => finding.rule === `${mutation}-file`));
  }
});

test("rejects a manifest under the wrong public key", async () => {
  const current = await fixture();
  const other = await fixture();
  assert.equal(create(current).status, 0);
  const result = verify(current, other.publicKey);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /another key/);
});
