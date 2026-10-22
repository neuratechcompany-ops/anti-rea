#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { chmod, copyFile, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rename, rm, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { verifyReleaseManifestEnvelope } from "./release-manifest.mjs";
import { verifyReleaseAttestationEnvelope } from "./release-attestation.mjs";
import { trustedRoleKey } from "./trust-bundle.mjs";
import { authorizeLiveRemoteTime, authorizeSignedRemoteTime } from "./time-attestation.mjs";

export const CAS_RECEIPT_FORMAT = "rea-hardening-cas-publisher-receipt/v2";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Buffer.from(JSON.stringify(value));

function bounded(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}
function integer(value, label) {
  if (!/^[1-9][0-9]{0,14}$/.test(value ?? "") || !Number.isSafeInteger(Number(value))) throw new Error(`${label} is invalid`);
  return Number(value);
}
function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields are invalid`);
}
function args(argv) {
  const options = {};
  const required = ["artifact", "cas-root", "release-manifest", "release-attestation", "trust-bundle", "trust-root-public-key", "time-ledger", "publisher-private-key", "product", "channel", "release", "minimum-sequence"];
  const allowed = new Set([...required, "time-attestation", "time-nonce", "time-authority-client"]);
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1]; const name = key?.slice(2);
    if (!key?.startsWith("--") || value === undefined || !allowed.has(name) || options[name] !== undefined) throw new Error("invalid arguments");
    options[name] = value;
  }
  for (const name of required) if (!options[name]) throw new Error(`--${name} is required`);
  if ((options["time-attestation"] === undefined) !== (options["time-nonce"] === undefined) || (options["time-authority-client"] !== undefined) === (options["time-attestation"] !== undefined)) throw new Error("provide exactly one live time authority client or file proof pair");
  if (options["time-nonce"] !== undefined && !/^[a-f0-9]{64}$/.test(options["time-nonce"])) throw new Error("--time-nonce must be 32-byte lowercase hex");
  bounded(options.product, "product"); bounded(options.channel, "channel"); bounded(options.release, "release"); integer(options["minimum-sequence"], "minimum-sequence");
  return options;
}
async function inventory(rootValue) {
  const root = await realpath(rootValue); const files = [];
  if (!(await lstat(root)).isDirectory()) throw new Error("artifact must be a directory");
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true }); entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name); const relative = path.relative(root, absolute).split(path.sep).join("/");
      if (entry.isSymbolicLink()) throw new Error(`artifact contains a symlink: ${relative}`);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile()) { const bytes = await readFile(absolute); files.push({ path: relative, bytes: bytes.length, sha256: sha256(bytes), source: absolute, executable: ((await stat(absolute)).mode & 0o111) !== 0 }); }
      else throw new Error(`artifact contains unsupported entry: ${relative}`);
    }
  }
  await visit(root); files.sort((a, b) => a.path.localeCompare(b.path));
  return { root, files, artifactSha256: sha256(Buffer.from(files.map((file) => `${file.path}\0${file.bytes}\0${file.sha256}`).join("\n"))) };
}
function manifestRows(payload) {
  if (!Array.isArray(payload?.files) || payload.files.some((file) => typeof file?.path !== "string" || !Number.isSafeInteger(file.bytes) || !/^[a-f0-9]{64}$/.test(file.sha256 ?? ""))) throw new Error("release manifest inventory is invalid");
  return payload.files.map(({ path: filePath, bytes, sha256: digest }) => ({ path: filePath, bytes, sha256: digest })).sort((a, b) => a.path.localeCompare(b.path));
}
function publicKeyId(key) { return sha256(createPublicKey(key).export({ type: "spki", format: "der" })); }
function signReceipt(payload, privateKey) {
  const payloadBytes = canonical(payload);
  return { format: CAS_RECEIPT_FORMAT, keyId: publicKeyId(privateKey), payload: payloadBytes.toString("base64"), signature: sign(null, Buffer.concat([Buffer.from(`${CAS_RECEIPT_FORMAT}\0`), payloadBytes]), privateKey).toString("base64") };
}
function verifyReceipt(bytes, trustBundle) {
  const envelope = JSON.parse(Buffer.from(bytes).toString("utf8")); exactKeys(envelope, ["format", "keyId", "payload", "signature"], "CAS receipt envelope");
  if (envelope.format !== CAS_RECEIPT_FORMAT || !/^[a-f0-9]{64}$/.test(envelope.keyId ?? "")) throw new Error("CAS receipt envelope is invalid");
  const key = createPublicKey(trustedRoleKey(trustBundle, "artifact-publisher", envelope.keyId).bytes); const payloadBytes = Buffer.from(envelope.payload, "base64");
  if (!verify(null, Buffer.concat([Buffer.from(`${CAS_RECEIPT_FORMAT}\0`), payloadBytes]), key, Buffer.from(envelope.signature, "base64"))) throw new Error("CAS receipt signature is invalid");
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  exactKeys(payload, ["artifactSha256", "channel", "clock", "object", "previous", "product", "publishedAt", "release", "releaseAttestationSha256", "releaseManifestSha256", "schemaVersion", "sequence", "trustBundleSha256"], "CAS receipt payload");
  exactKeys(payload.clock, ["attestationSha256", "consumptionSha256", "keyId", "nonce", "requestSha256", "source", "verifierRunId"], "CAS receipt clock");
  if (payload.schemaVersion !== 2 || payload.clock.source !== "signed-live" || Object.values(payload.clock).some((value) => value !== "signed-live" && !/^[a-f0-9]{64}$/.test(value)) || !Number.isSafeInteger(payload.sequence) || payload.sequence < 1) throw new Error("CAS receipt payload is invalid");
  return { envelope, payload, sha256: sha256(Buffer.from(bytes)) };
}
async function copyObject(sourceInventory, stagingRoot) {
  const payloadRoot = path.join(stagingRoot, "payload"); await mkdir(payloadRoot, { recursive: true, mode: 0o755 });
  const directories = new Set([payloadRoot]);
  for (const file of sourceInventory.files) {
    const destination = path.join(payloadRoot, ...file.path.split("/")); const directory = path.dirname(destination); await mkdir(directory, { recursive: true, mode: 0o755 }); directories.add(directory);
    await copyFile(file.source, destination); await chmod(destination, file.executable ? 0o555 : 0o444);
  }
  for (const directory of [...directories].sort((a, b) => b.length - a.length)) await chmod(directory, 0o555);
  await chmod(stagingRoot, 0o555);
}
async function writeExclusive(file, bytes) { const handle = await open(file, "wx", 0o444); try { await handle.writeFile(bytes); } finally { await handle.close(); } }

async function publish(options) {
  const artifact = await inventory(options.artifact);
  await mkdir(path.resolve(options["cas-root"]), { recursive: true, mode: 0o755 }); const casRoot = await realpath(path.resolve(options["cas-root"]));
  if (casRoot === artifact.root || casRoot.startsWith(`${artifact.root}${path.sep}`)) throw new Error("CAS root must be outside the mutable artifact");
  const trustBundleBytes = await readFile(path.resolve(options["trust-bundle"]));
  const attestationBytes = await readFile(path.resolve(options["release-attestation"]));
  const timeCommon = { trustBundleBytes, trustRootPublicKeyBytes: await readFile(path.resolve(options["trust-root-public-key"])), product: options.product, evaluationId: `publish:${sha256(attestationBytes)}`, ledgerRoot: options["time-ledger"] };
  const time = options["time-authority-client"]
    ? await authorizeLiveRemoteTime({ ...timeCommon, authorityClient: options["time-authority-client"] })
    : await authorizeSignedRemoteTime({ ...timeCommon, timeAttestationBytes: await readFile(path.resolve(options["time-attestation"])), nonce: options["time-nonce"] });
  const clock = time.clock; const trustBundle = time.trustBundle;
  const attestation = verifyReleaseAttestationEnvelope(attestationBytes, trustBundle, { product: options.product, channel: options.channel, release: options.release, minimumSequence: integer(options["minimum-sequence"], "minimum-sequence"), clock });
  if (attestation.payload.bindings.trustBundleSha256 !== sha256(trustBundleBytes)) throw new Error("release attestation is not bound to the pinned trust bundle");
  const manifestBytes = await readFile(path.resolve(options["release-manifest"]));
  const manifestEnvelope = JSON.parse(manifestBytes.toString("utf8"));
  const manifest = verifyReleaseManifestEnvelope(manifestBytes, trustedRoleKey(trustBundle, "release-manifest", manifestEnvelope.keyId).bytes, options.product, options.release);
  if (sha256(manifestBytes) !== attestation.payload.bindings.releaseManifestSha256) throw new Error("release manifest is not bound by the release attestation");
  const expectedRows = manifestRows(manifest.payload); const actualRows = artifact.files.map(({ path: p, bytes, sha256: digest }) => ({ path: p, bytes, sha256: digest }));
  if (JSON.stringify(expectedRows) !== JSON.stringify(actualRows) || artifact.artifactSha256 !== attestation.payload.artifactSha256) throw new Error("mutable artifact does not match the attested release inventory");
  const publisherPrivateKey = createPrivateKey({ key: await readFile(path.resolve(options["publisher-private-key"])), passphrase: process.env.REA_PUBLISHER_PASSPHRASE });
  if (publisherPrivateKey.asymmetricKeyType !== "ed25519") throw new Error("publisher private key must be Ed25519");
  trustedRoleKey(trustBundle, "artifact-publisher", publicKeyId(publisherPrivateKey));

  const channelId = sha256(Buffer.from(`${options.product}\0${options.channel}`));
  const locksRoot = path.join(casRoot, "locks"); const objectsRoot = path.join(casRoot, "objects", "sha256"); const channelsRoot = path.join(casRoot, "channels", channelId); const releasesRoot = path.join(casRoot, "releases", channelId);
  await mkdir(locksRoot, { recursive: true }); await mkdir(objectsRoot, { recursive: true }); await mkdir(channelsRoot, { recursive: true }); await mkdir(releasesRoot, { recursive: true });
  const lock = path.join(locksRoot, `${channelId}.lock`); await mkdir(lock);
  let staging = null;
  try {
    const headPath = path.join(channelsRoot, "head.json"); let head = null;
    try { head = verifyReceipt(await readFile(headPath), trustBundle); } catch (error) { if (error?.code !== "ENOENT") throw error; }
    if (head && head.payload.sequence === attestation.payload.sequence && head.payload.releaseAttestationSha256 === attestation.sha256) return { status: "already-published", artifactSha256: artifact.artifactSha256, sequence: head.payload.sequence, object: head.payload.object, receipt: headPath };
    if (attestation.payload.sequence === 1) { if (head !== null) throw new Error("channel already has a head; genesis fork rejected"); }
    else {
      if (!head || head.payload.sequence !== attestation.payload.sequence - 1) throw new Error("publisher channel head is not the immediate predecessor");
      if (attestation.payload.previous?.attestationSha256 !== head.payload.releaseAttestationSha256) throw new Error("release predecessor does not match the publisher channel head");
    }
    const objectRelative = `objects/sha256/${artifact.artifactSha256}`; const objectPath = path.join(casRoot, objectRelative);
    try {
      const current = await inventory(path.join(objectPath, "payload")); if (current.artifactSha256 !== artifact.artifactSha256) throw new Error("existing CAS object digest mismatch");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      staging = await mkdtemp(path.join(objectsRoot, ".stage-")); await copyObject(artifact, staging); await rename(staging, objectPath); staging = null;
    }
    const previous = head === null ? null : { sequence: head.payload.sequence, receiptSha256: head.sha256, releaseAttestationSha256: head.payload.releaseAttestationSha256 };
    const receiptPayload = { schemaVersion: 2, product: options.product, channel: options.channel, release: options.release, sequence: attestation.payload.sequence, artifactSha256: artifact.artifactSha256, object: objectRelative, releaseAttestationSha256: attestation.sha256, releaseManifestSha256: sha256(manifestBytes), trustBundleSha256: sha256(trustBundleBytes), publishedAt: clock.observedAt, clock: { source: clock.source, keyId: clock.keyId, attestationSha256: clock.attestationSha256, nonce: clock.nonce, consumptionSha256: clock.consumptionSha256, requestSha256: clock.requestSha256, verifierRunId: clock.verifierRunId }, previous };
    const receiptBytes = Buffer.from(`${JSON.stringify(signReceipt(receiptPayload, publisherPrivateKey), null, 2)}\n`); const receiptPath = path.join(releasesRoot, `${attestation.payload.sequence}.json`); await writeExclusive(receiptPath, receiptBytes);
    const temporaryHead = path.join(channelsRoot, `.head-${process.pid}-${Date.now()}.json`); await writeExclusive(temporaryHead, receiptBytes); await rename(temporaryHead, headPath);
    return { status: "published", artifactSha256: artifact.artifactSha256, sequence: attestation.payload.sequence, object: objectRelative, receipt: receiptPath, head: headPath };
  } finally {
    if (staging !== null) await rm(staging, { recursive: true, force: true });
    await rm(lock, { recursive: true, force: true });
  }
}

async function main() { const result = await publish(args(process.argv.slice(2))); process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); }
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`CAS publisher error: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
