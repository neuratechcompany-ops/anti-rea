import { createHash } from "node:crypto";
import { lstat, readFile, readdir, readlink, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));

function packagePath(value) {
  if (typeof value !== "string" || !value.startsWith("node_modules/") || value.includes("\\") || value.split("/").includes("..")) throw new Error(`dependency lock path is unsafe: ${String(value)}`);
  const parts = value.split("/");
  if (parts.at(-1) === "node_modules" || parts.some((part) => !part)) throw new Error(`dependency lock path is invalid: ${value}`);
  return parts;
}

async function treeInventory(root) {
  const files = [];
  async function visit(directory, relativeDirectory = "") {
    const entries = await readdir(directory, { withFileTypes: true }); entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.name === "node_modules" && entry.isDirectory()) continue;
      const absolute = path.join(directory, entry.name); const relative = path.join(relativeDirectory, entry.name).split(path.sep).join("/"); const metadata = await lstat(absolute);
      if (metadata.isSymbolicLink()) throw new Error(`dependency package contains a symlink: ${relative}`);
      if (metadata.isDirectory()) await visit(absolute, relative);
      else if (metadata.isFile()) { const bytes = await readFile(absolute); files.push({ path: relative, bytes: bytes.length, mode: metadata.mode & 0o777, sha256: sha256(bytes) }); }
      else throw new Error(`dependency package contains an unsupported entry: ${relative}`);
    }
  }
  await visit(root); files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, sha256: sha256(Buffer.from(files.map((file) => `${file.path}\0${file.bytes}\0${file.mode}\0${file.sha256}`).join("\n"))) };
}

async function installedPackagePaths(nodeModulesRoot, repositoryRoot) {
  const found = new Set();
  async function scanModules(directory) {
    let entries;
    try { entries = await readdir(directory, { withFileTypes: true }); } catch (error) { if (error?.code === "ENOENT") return; throw error; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.name === ".bin" || entry.name === ".package-lock.json") continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`installed dependency is a symlink: ${path.relative(repositoryRoot, absolute)}`);
      if (!entry.isDirectory()) throw new Error(`unexpected node_modules entry: ${path.relative(repositoryRoot, absolute)}`);
      if (entry.name.startsWith("@")) {
        const scoped = await readdir(absolute, { withFileTypes: true }); scoped.sort((a, b) => a.name.localeCompare(b.name));
        for (const child of scoped) {
          const childAbsolute = path.join(absolute, child.name);
          if (child.isSymbolicLink() || !child.isDirectory()) throw new Error(`invalid scoped dependency: ${path.relative(repositoryRoot, childAbsolute)}`);
          found.add(path.relative(repositoryRoot, childAbsolute).split(path.sep).join("/")); await scanModules(path.join(childAbsolute, "node_modules"));
        }
      } else {
        found.add(path.relative(repositoryRoot, absolute).split(path.sep).join("/")); await scanModules(path.join(absolute, "node_modules"));
      }
    }
  }
  await scanModules(nodeModulesRoot); return found;
}

async function binInventory(root) {
  const directory = path.join(root, "node_modules", ".bin"); let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); } catch (error) { if (error?.code === "ENOENT") return []; throw error; }
  entries.sort((a, b) => a.name.localeCompare(b.name)); const bins = [];
  for (const entry of entries) {
    if (!entry.name || entry.name.includes("/") || entry.name.includes("\\")) throw new Error("dependency executable shim name is invalid");
    const absolute = path.join(directory, entry.name); const metadata = await lstat(absolute);
    if (metadata.isSymbolicLink()) {
      const target = await readlink(absolute); const resolved = await realpath(absolute); const modulesRoot = path.join(root, "node_modules");
      if (resolved !== modulesRoot && !resolved.startsWith(`${modulesRoot}${path.sep}`)) throw new Error(`dependency executable shim escapes node_modules: ${entry.name}`);
      bins.push({ name: entry.name, kind: "symlink", target: target.split(path.sep).join("/"), targetSha256: sha256(await readFile(resolved)) });
    } else if (metadata.isFile()) {
      const bytes = await readFile(absolute); bins.push({ name: entry.name, kind: "file", bytes: bytes.length, mode: metadata.mode & 0o777, sha256: sha256(bytes) });
    } else throw new Error(`dependency executable shim is unsupported: ${entry.name}`);
  }
  return bins;
}

export async function inspectDependencyClosure(rootValue) {
  const root = await realpath(path.resolve(rootValue)); const packageJsonBytes = await readFile(path.join(root, "package.json")); const lockBytes = await readFile(path.join(root, "package-lock.json"));
  const packageJson = JSON.parse(packageJsonBytes.toString("utf8")); const lock = JSON.parse(lockBytes.toString("utf8"));
  if (!Number.isSafeInteger(lock.lockfileVersion) || lock.lockfileVersion < 2 || !lock.packages || typeof lock.packages !== "object" || Array.isArray(lock.packages)) throw new Error("package-lock must use packages schema v2 or newer");
  if (lock.packages[""]?.name !== packageJson.name || lock.packages[""]?.version !== packageJson.version) throw new Error("package-lock root identity differs from package.json");
  const declared = Object.entries(lock.packages).filter(([name]) => name !== "").sort(([a], [b]) => a.localeCompare(b)); const installed = await installedPackagePaths(path.join(root, "node_modules"), root); const packages = [];
  for (const [lockPath, declaration] of declared) {
    const parts = packagePath(lockPath); const absolute = path.join(root, ...parts); let metadata;
    try { metadata = await lstat(absolute); } catch (error) {
      if (error?.code === "ENOENT" && declaration?.optional === true) { packages.push({ path: lockPath, version: declaration.version, integrity: declaration.integrity ?? null, optional: true, present: false, treeSha256: null }); continue; }
      if (error?.code === "ENOENT") throw new Error(`required dependency is not installed: ${lockPath}`); throw error;
    }
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error(`installed dependency is not a regular directory: ${lockPath}`);
    const identity = JSON.parse(await readFile(path.join(absolute, "package.json"), "utf8"));
    if (typeof declaration?.version !== "string" || identity.version !== declaration.version || typeof identity.name !== "string") throw new Error(`installed dependency identity differs from lockfile: ${lockPath}`);
    const inventory = await treeInventory(absolute); installed.delete(lockPath);
    packages.push({ path: lockPath, name: identity.name, version: declaration.version, integrity: declaration.integrity ?? null, optional: declaration.optional === true, present: true, treeSha256: inventory.sha256 });
  }
  if (installed.size) throw new Error(`node_modules contains packages absent from lockfile: ${[...installed].sort()[0]}`);
  const bins = await binInventory(root);
  const core = { schemaVersion: 1, packageJsonSha256: sha256(packageJsonBytes), packageLockSha256: sha256(lockBytes), lockfileVersion: lock.lockfileVersion, packages, bins };
  return { ...core, closureSha256: sha256(canonical(core)) };
}

async function main() {
  const argv = process.argv.slice(2); if (argv.length !== 2 || argv[0] !== "--root") throw new Error("usage: dependency-closure.mjs --root PROTECTOR_REPOSITORY");
  process.stdout.write(`${JSON.stringify(await inspectDependencyClosure(argv[1]), null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`dependency closure error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
