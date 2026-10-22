#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { lstat, open, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const RELEASE_MANIFEST_FORMAT = "rea-hardening-release/v1";

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write([
    "usage:",
    "  release-manifest.mjs create --root DIR --private-key PEM --product NAME --release VERSION --out NEW_FILE",
    "  release-manifest.mjs verify --root DIR --public-key PEM --product NAME --release VERSION --manifest FILE",
  ].join("\n") + "\n");
  process.exit(64);
}

function args(argv) {
  const mode = argv.shift();
  if (!new Set(["create", "verify"]).has(mode)) usage("mode must be create or verify");
  const result = { mode };
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) usage("invalid arguments");
    const name = key.slice(2);
    if (result[name] !== undefined) usage(`duplicate argument: ${key}`);
    result[name] = value;
  }
  const required = mode === "create"
    ? ["root", "private-key", "product", "release", "out"]
    : ["root", "public-key", "product", "release", "manifest"];
  for (const name of required) if (!result[name]) usage(`--${name} is required`);
  return result;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function boundedText(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`invalid ${label}`);
  return value;
}

function canonical(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8");
}

async function inventory(rootValue) {
  const root = await realpath(rootValue);
  if (!(await lstat(root)).isDirectory()) throw new Error("root must be a directory");
  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      if (entry.isSymbolicLink()) throw new Error(`release contains a symlink: ${relative}`);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile()) {
        const bytes = await readFile(absolute);
        files.push({ path: relative, bytes: bytes.length, sha256: sha256(bytes) });
      } else throw new Error(`release contains an unsupported entry: ${relative}`);
    }
  }
  await visit(root);
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return { root, files };
}

function validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("invalid manifest payload");
  if (Object.keys(payload).sort().join("|") !== ["files", "product", "release", "schemaVersion"].sort().join("|")) throw new Error("unexpected manifest payload fields");
  if (payload.schemaVersion !== 1) throw new Error("unsupported manifest schema");
  boundedText(payload.product, "product");
  boundedText(payload.release, "release");
  if (!Array.isArray(payload.files)) throw new Error("manifest files must be an array");
  let previous = "";
  for (const file of payload.files) {
    if (!file || typeof file !== "object" || Array.isArray(file) || Object.keys(file).sort().join("|") !== "bytes|path|sha256") throw new Error("invalid manifest file entry");
    if (typeof file.path !== "string" || !file.path || file.path.startsWith("/") || file.path.includes("\\") || file.path.split("/").some((part) => !part || part === "." || part === "..")) throw new Error("unsafe manifest path");
    if (file.path <= previous) throw new Error("manifest paths must be unique and sorted");
    previous = file.path;
    if (!Number.isSafeInteger(file.bytes) || file.bytes < 0 || !/^[a-f0-9]{64}$/.test(file.sha256)) throw new Error("invalid manifest file metadata");
  }
}

async function writeExclusive(destination, content) {
  const handle = await open(destination, "wx", 0o644);
  try {
    await handle.writeFile(content);
  } finally {
    await handle.close();
  }
}

async function create(options) {
  const { files } = await inventory(options.root);
  const payload = { schemaVersion: 1, product: boundedText(options.product, "product"), release: boundedText(options.release, "release"), files };
  const payloadBytes = canonical(payload);
  const privateKey = createPrivateKey({ key: await readFile(options["private-key"]), passphrase: process.env.REA_MANIFEST_PASSPHRASE });
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("private key must be Ed25519");
  const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const envelope = {
    format: RELEASE_MANIFEST_FORMAT,
    keyId: sha256(publicDer),
    payload: payloadBytes.toString("base64"),
    signature: sign(null, Buffer.concat([Buffer.from(`${RELEASE_MANIFEST_FORMAT}\0`), payloadBytes]), privateKey).toString("base64"),
  };
  await writeExclusive(path.resolve(options.out), `${JSON.stringify(envelope, null, 2)}\n`);
  return { status: "created", files: files.length, keyId: envelope.keyId, manifest: path.resolve(options.out) };
}

export function verifyReleaseManifestEnvelope(envelopeBytes, publicKeyBytes, product, release) {
  const envelope = JSON.parse(Buffer.from(envelopeBytes).toString("utf8"));
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || Object.keys(envelope).sort().join("|") !== "format|keyId|payload|signature") throw new Error("invalid manifest envelope");
  if (envelope.format !== RELEASE_MANIFEST_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId)) throw new Error("invalid manifest format or key id");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  const signature = Buffer.from(envelope.signature, "base64");
  const publicKey = createPublicKey(publicKeyBytes);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("public key must be Ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (sha256(publicDer) !== envelope.keyId) throw new Error("manifest was signed by another key");
  if (!verify(null, Buffer.concat([Buffer.from(`${RELEASE_MANIFEST_FORMAT}\0`), payloadBytes]), publicKey, signature)) throw new Error("manifest signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  validatePayload(payload);
  if (!canonical(payload).equals(payloadBytes)) throw new Error("manifest payload is not canonical");
  if (payload.product !== product || payload.release !== release) throw new Error("manifest product or release does not match the trusted expectation");
  return { payload, keyId: envelope.keyId };
}

async function verifyManifest(options) {
  const verified = verifyReleaseManifestEnvelope(await readFile(options.manifest), await readFile(options["public-key"]), options.product, options.release);
  const { payload } = verified;

  const { files } = await inventory(options.root);
  const expected = new Map(payload.files.map((file) => [file.path, file]));
  const actual = new Map(files.map((file) => [file.path, file]));
  const findings = [];
  for (const [name, file] of expected) {
    if (!actual.has(name)) findings.push({ rule: "missing-file", path: name });
    else if (actual.get(name).bytes !== file.bytes || actual.get(name).sha256 !== file.sha256) findings.push({ rule: "modified-file", path: name });
  }
  for (const name of actual.keys()) if (!expected.has(name)) findings.push({ rule: "extra-file", path: name });
  findings.sort((a, b) => a.path.localeCompare(b.path) || a.rule.localeCompare(b.rule));
  return { status: findings.length === 0 ? "verified" : "failed", files: files.length, keyId: verified.keyId, findings };
}

async function main() {
  const options = args(process.argv.slice(2));
  const result = options.mode === "create" ? await create(options) : await verifyManifest(options);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.status === "failed") process.exitCode = 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => {
  process.stderr.write(`release manifest error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
