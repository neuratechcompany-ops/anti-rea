import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { verifyProductBuildAttestation } from "../scripts/product-build-attestation.mjs";

const root = path.resolve(import.meta.dirname, ".."); const tool = path.join(root, "scripts", "product-build-attestation.mjs");
const sha = (value) => createHash("sha256").update(value).digest("hex");

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-product-build-")); const repository = path.join(directory, "product");
  const init = spawnSync("git", ["init", repository], { encoding: "utf8" }); assert.equal(init.status, 0, init.stderr);
  const buildDefinition = path.join(repository, "build.mjs"); await writeFile(buildDefinition, "export const build = true;\n");
  for (const values of [["config", "user.email", "test@example.invalid"], ["config", "user.name", "Test"], ["remote", "add", "origin", "https://example.invalid/owned.git"], ["add", "."], ["commit", "-m", "owned product"]]) {
    const result = spawnSync("git", values, { cwd: repository, encoding: "utf8" }); assert.equal(result.status, 0, result.stderr);
  }
  const input = path.join(directory, "bundle.js"); await writeFile(input, "owned build output\n");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519"); const privatePath = path.join(directory, "private.pem"); const publicPath = path.join(directory, "public.pem");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" })); await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }));
  const keyId = sha(publicKey.export({ type: "spki", format: "der" })); const environmentSha256 = sha(Buffer.from("builder-image")); const output = path.join(directory, "build.attestation.json");
  const args = [tool, "sign", "--product", "OwnedProduct", "--product-root", repository, "--repository-uri", "https://example.invalid/owned.git", "--build-definition", buildDefinition, "--virtualization-input", input, "--builder-id", "owned-builder", "--environment-sha256", environmentSha256, "--private-key", privatePath, "--run-id", "build-1", "--expires-at", new Date(Date.now() + 60 * 60 * 1000).toISOString(), "--out", output];
  return { directory, repository, buildDefinition, input, privatePath, publicPath, keyId, environmentSha256, output, args };
}

test("binds owner-approved product commit and build definition to virtualization input", async () => {
  const value = await fixture(); const signed = spawnSync(process.execPath, value.args, { encoding: "utf8" }); assert.equal(signed.status, 0, signed.stderr);
  const result = JSON.parse(signed.stdout); const buildDefinitionSha256 = sha(await readFile(value.buildDefinition));
  const verified = verifyProductBuildAttestation(await readFile(value.output), await readFile(value.publicPath), {
    product: "OwnedProduct", repositoryUri: "https://example.invalid/owned.git", commit: result.commit, tree: result.tree,
    buildDefinitionSha256, builderId: "owned-builder", builderKeyId: value.keyId, builderEnvironmentSha256: value.environmentSha256,
    virtualizationInputSha256: sha(await readFile(value.input)),
  });
  assert.equal(verified.payload.virtualizationInputSha256, result.virtualizationInputSha256);
});

test("rejects dirty source and owner-policy identity mismatch", async () => {
  const dirty = await fixture(); await writeFile(path.join(dirty.repository, "untracked.txt"), "dirty\n");
  const rejected = spawnSync(process.execPath, dirty.args, { encoding: "utf8" }); assert.equal(rejected.status, 1); assert.match(rejected.stderr, /repository is dirty/);

  const value = await fixture(); assert.equal(spawnSync(process.execPath, value.args, { encoding: "utf8" }).status, 0);
  const envelopeBytes = await readFile(value.output); const publicKeyBytes = await readFile(value.publicPath);
  const signed = JSON.parse(Buffer.from(JSON.parse(envelopeBytes.toString("utf8")).payload, "base64").toString("utf8"));
  assert.throws(() => verifyProductBuildAttestation(envelopeBytes, publicKeyBytes, {
    product: "OwnedProduct", repositoryUri: "https://example.invalid/owned.git", commit: "0".repeat(40), tree: signed.tree,
    buildDefinitionSha256: signed.buildDefinitionSha256, builderId: "owned-builder", builderKeyId: value.keyId, builderEnvironmentSha256: value.environmentSha256,
  }), /commit mismatch/);
});
