import assert from "node:assert/strict";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { inspectDependencyClosure } from "../scripts/dependency-closure.mjs";

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "anti-rea-dependencies-")); await mkdir(path.join(root, "node_modules", "example-dependency"), { recursive: true });
  await writeFile(path.join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { "example-dependency": "2.0.0" } }));
  await writeFile(path.join(root, "package-lock.json"), JSON.stringify({ name: "fixture", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "fixture", version: "1.0.0" }, "node_modules/example-dependency": { version: "2.0.0", integrity: "sha512-fixture" } } }));
  await writeFile(path.join(root, "node_modules", "example-dependency", "package.json"), JSON.stringify({ name: "example-dependency", version: "2.0.0" }));
  await writeFile(path.join(root, "node_modules", "example-dependency", "index.js"), "export const value = 1;\n"); return root;
}

test("binds the installed dependency bytes, mode, identity, and lockfile", async () => {
  const root = await fixture(); const first = await inspectDependencyClosure(root); assert.equal(first.packages.length, 1); assert.equal(first.packages[0].name, "example-dependency"); assert.match(first.closureSha256, /^[a-f0-9]{64}$/);
  await writeFile(path.join(root, "node_modules", "example-dependency", "index.js"), "export const value = 2;\n"); const second = await inspectDependencyClosure(root); assert.notEqual(second.closureSha256, first.closureSha256); assert.notEqual(second.packages[0].treeSha256, first.packages[0].treeSha256);
});

test("rejects missing, extra, and symlinked installed packages", async () => {
  const missing = await fixture(); await writeFile(path.join(missing, "package-lock.json"), JSON.stringify({ name: "fixture", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "fixture", version: "1.0.0" }, "node_modules/missing": { version: "1.0.0" }, "node_modules/example-dependency": { version: "2.0.0" } } })); await assert.rejects(inspectDependencyClosure(missing), /required dependency is not installed/);
  const extra = await fixture(); await mkdir(path.join(extra, "node_modules", "undeclared")); await writeFile(path.join(extra, "node_modules", "undeclared", "package.json"), JSON.stringify({ name: "undeclared", version: "1.0.0" })); await assert.rejects(inspectDependencyClosure(extra), /absent from lockfile/);
  const linked = await fixture(); await symlink(path.join(linked, "package.json"), path.join(linked, "node_modules", "example-dependency", "escape")); await assert.rejects(inspectDependencyClosure(linked), /contains a symlink/);
  const escapedBin = await fixture(); await mkdir(path.join(escapedBin, "node_modules", ".bin")); await symlink(path.join(escapedBin, "package.json"), path.join(escapedBin, "node_modules", ".bin", "escape")); await assert.rejects(inspectDependencyClosure(escapedBin), /escapes node_modules/);
});

test("records an unavailable optional package without accepting missing required code", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "anti-rea-optional-")); await writeFile(path.join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0" })); await writeFile(path.join(root, "package-lock.json"), JSON.stringify({ name: "fixture", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "fixture", version: "1.0.0" }, "node_modules/platform-only": { version: "1.0.0", optional: true } } }));
  const result = await inspectDependencyClosure(root); assert.deepEqual(result.packages[0], { path: "node_modules/platform-only", version: "1.0.0", integrity: null, optional: true, present: false, treeSha256: null });
});
