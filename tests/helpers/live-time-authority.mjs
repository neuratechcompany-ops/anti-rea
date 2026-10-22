import { chmod, writeFile } from "node:fs/promises";
import path from "node:path";

export async function createLiveTimeAuthorityClient(directory, privateKey, name = "time-authority-client.mjs") {
  const destination = path.join(directory, name); const modulePath = path.resolve(import.meta.dirname, "..", "..", "scripts", "time-attestation.mjs"); const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  await writeFile(destination, `#!/usr/bin/env node\nimport crypto from "node:crypto";import {createTimeAttestationEnvelope} from ${JSON.stringify(modulePath)};let input="";for await(const chunk of process.stdin)input+=chunk;const request=JSON.parse(input);const envelope=createTimeAttestationEnvelope({schemaVersion:1,product:request.product,environment:request.environment,evaluationId:request.evaluationId,nonce:request.nonce,authorityRunId:crypto.randomBytes(32).toString("hex"),observedAt:new Date().toISOString()},${JSON.stringify(privatePem)});process.stdout.write(JSON.stringify(envelope));\n`); await chmod(destination, 0o755); return destination;
}
