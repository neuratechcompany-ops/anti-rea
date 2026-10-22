import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { verifyProtectionTransform } from "../scripts/protection-transform.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const policy = { virtualizerName: "anti-rea-selective-vm", virtualizerVersion: "1.2.0", keyMode: "external", encryption: "chacha20-poly1305", transformerName: "javascript-obfuscator", transformerVersion: "5.9.0", profileId: "javascript-vm-balanced", profileSha256: "1".repeat(64), claimTier: "T1" };

function receipts(provider = "function-v1") {
  const virtualization = { schemaVersion: 1, transformer: { name: policy.virtualizerName, version: policy.virtualizerVersion }, key: { mode: "external", provider, encryption: policy.encryption }, input: { sha256: "2".repeat(64) }, output: { sha256: "3".repeat(64) }, functions: [{ id: "4".repeat(64) }], canaries: { sha256: ["5".repeat(64)] } };
  const virtualizationBytes = Buffer.from(JSON.stringify(virtualization));
  const transform = { schemaVersion: 1, transformer: { name: policy.transformerName, version: policy.transformerVersion }, profile: { id: policy.profileId, sha256: policy.profileSha256 }, upstream: { virtualization: { sha256: sha(virtualizationBytes), canarySha256: virtualization.canaries.sha256 } }, input: { sha256: virtualization.output.sha256 }, output: { sha256: "6".repeat(64) } };
  return { virtualizationBytes, transformBytes: Buffer.from(JSON.stringify(transform)) };
}

test("accepts the owner-pinned function-v1 external key provider contract", () => {
  const value = receipts(); const result = verifyProtectionTransform(policy, value.virtualizationBytes, value.transformBytes); assert.equal(result.virtualization.key.provider, "function-v1");
});

test("rejects an external VM receipt that falls back to a string key slot", () => {
  const value = receipts("global-string-v0"); assert.throws(() => verifyProtectionTransform(policy, value.virtualizationBytes, value.transformBytes), /key provider contract is invalid/);
});
