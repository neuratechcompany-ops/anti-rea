import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { verifyCrossBuildVariantEnvelope } from "../scripts/cross-build-variant-attestation.mjs";

const root = path.resolve(import.meta.dirname, ".."); const cli = path.join(root, "scripts", "cross-build-variant-attestation.mjs");

async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), "anti-rea-variant-attestation-")); const { privateKey, publicKey } = generateKeyPairSync("ed25519"); const privatePath = path.join(directory, "private.pem"); const publicPath = path.join(directory, "public.pem");
  await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" })); await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }));
  const payload = { schemaVersion: 1, product: "Example", policySha256: "1".repeat(64), repositoryUri: "https://example.invalid/product.git", commit: "2".repeat(40), tree: "3".repeat(40), buildDefinitionSha256: "4".repeat(64), builderId: "isolated-builder", builderEnvironmentSha256: "5".repeat(64), runId: "variant-run-0", variantOrdinal: 0, diversitySeedCommitment: "6".repeat(64), regionSha256: "7".repeat(64), issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() };
  const descriptor = path.join(directory, "descriptor.json"); const output = path.join(directory, "attestation.json"); await writeFile(descriptor, JSON.stringify(payload)); return { directory, privatePath, publicPath, payload, descriptor, output };
}

test("binds one diversified region to owner-approved source, policy, builder, and run", async () => {
  const value = await fixture(); const result = spawnSync(process.execPath, [cli, "sign", "--descriptor", value.descriptor, "--private-key", value.privatePath, "--out", value.output], { encoding: "utf8" }); assert.equal(result.status, 0, result.stderr);
  const verified = verifyCrossBuildVariantEnvelope(await readFile(value.output), await readFile(value.publicPath), { policySha256: value.payload.policySha256, regionSha256: value.payload.regionSha256, variantOrdinal: 0 }); assert.equal(verified.payload.runId, "variant-run-0");
});

test("rejects a substituted region or modified builder statement", async () => {
  const value = await fixture(); let result = spawnSync(process.execPath, [cli, "sign", "--descriptor", value.descriptor, "--private-key", value.privatePath, "--out", value.output], { encoding: "utf8" }); assert.equal(result.status, 0, result.stderr);
  const publicBytes = await readFile(value.publicPath); let envelopeBytes = await readFile(value.output); assert.throws(() => verifyCrossBuildVariantEnvelope(envelopeBytes, publicBytes, { regionSha256: "8".repeat(64) }), /regionSha256 mismatch/);
  const envelope = JSON.parse(await readFile(value.output, "utf8")); envelope.payload = Buffer.from(JSON.stringify({ ...value.payload, runId: "forged" })).toString("base64"); await writeFile(value.output, JSON.stringify(envelope)); envelopeBytes = await readFile(value.output); assert.throws(() => verifyCrossBuildVariantEnvelope(envelopeBytes, publicBytes), /signature is invalid/);
});
