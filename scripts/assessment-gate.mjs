import { createHash, createPublicKey, verify } from "node:crypto";

export const ASSESSMENT_GATE_FORMAT = "rea-hardening-assessment-gate/v1";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function verifyAssessmentGate(result, publicKeyBytes) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("assessment result is invalid");
  const { gateAttestation, ...core } = result;
  if (!gateAttestation || typeof gateAttestation !== "object" || Array.isArray(gateAttestation) || Object.keys(gateAttestation).sort().join("|") !== ["format", "keyId", "signature"].sort().join("|")) throw new Error("assessment result lacks a gate attestation");
  if (gateAttestation.format !== ASSESSMENT_GATE_FORMAT || !/^[a-f0-9]{64}$/.test(gateAttestation.keyId ?? "") || typeof gateAttestation.signature !== "string") throw new Error("assessment gate attestation is invalid");
  const publicKey = createPublicKey(publicKeyBytes);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("assessment gate public key must be Ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (sha256(publicDer) !== gateAttestation.keyId) throw new Error("assessment gate key is not trusted");
  const coreBytes = Buffer.from(JSON.stringify(core));
  if (!verify(null, Buffer.concat([Buffer.from(`${ASSESSMENT_GATE_FORMAT}\0`), coreBytes]), publicKey, Buffer.from(gateAttestation.signature, "base64"))) throw new Error("assessment gate signature is invalid");
  return { keyId: gateAttestation.keyId, core };
}
