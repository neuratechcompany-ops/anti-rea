import { createHash } from "node:crypto";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const digest = (value, label) => {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} must be lowercase SHA-256 hex`);
  return value;
};

export function verifyProtectionTransform(policy, virtualizationBytes, transformBytes) {
  const virtualizationSha256 = sha256(virtualizationBytes); const transformSha256 = sha256(transformBytes);
  const virtualization = JSON.parse(Buffer.from(virtualizationBytes).toString("utf8")); const transform = JSON.parse(Buffer.from(transformBytes).toString("utf8"));
  if (virtualization?.schemaVersion !== 1 || virtualization?.transformer?.name !== policy.virtualizerName || virtualization?.transformer?.version !== policy.virtualizerVersion) throw new Error("virtualization receipt does not match the owner-signed virtualizer identity");
  if (virtualization?.key?.mode !== policy.keyMode || virtualization?.key?.encryption !== policy.encryption) throw new Error("virtualization receipt key mode or encryption differs from owner policy");
  if ((policy.keyMode === "external" && virtualization?.key?.provider !== "function-v1") || (policy.keyMode === "embedded" && virtualization?.key?.provider !== null)) throw new Error("virtualization receipt key provider contract is invalid");
  digest(virtualization?.input?.sha256, "virtualization.input.sha256"); digest(virtualization?.output?.sha256, "virtualization.output.sha256");
  if (!Array.isArray(virtualization?.functions) || virtualization.functions.length < 1) throw new Error("virtualization receipt contains no protected functions");
  const functionIds = virtualization.functions.map((item) => item?.id).sort();
  if (functionIds.some((item) => !/^[a-f0-9]{64}$/.test(item)) || new Set(functionIds).size !== functionIds.length) throw new Error("virtualization receipt protected function IDs are invalid or duplicate");
  if (!Array.isArray(virtualization?.canaries?.sha256) || virtualization.canaries.sha256.some((item) => !/^[a-f0-9]{64}$/.test(item))) throw new Error("virtualization receipt canaries are invalid");
  if (transform?.schemaVersion !== 1 || transform?.transformer?.name !== policy.transformerName || transform?.transformer?.version !== policy.transformerVersion) throw new Error("transform receipt does not match the owner-signed transformer identity");
  if (transform?.profile?.id !== policy.profileId || transform?.profile?.sha256 !== policy.profileSha256) throw new Error("transform receipt profile differs from owner policy");
  if (transform?.upstream?.virtualization?.sha256 !== virtualizationSha256 || transform?.input?.sha256 !== virtualization.output.sha256) throw new Error("transform receipt is not bound to virtualization");
  if (JSON.stringify(transform?.upstream?.virtualization?.canarySha256) !== JSON.stringify(virtualization.canaries.sha256)) throw new Error("transform receipt canaries differ from virtualization");
  digest(transform?.output?.sha256, "transform.output.sha256");
  return { virtualization, transform, virtualizationSha256, transformSha256, functionIds, claimTier: policy.claimTier };
}
