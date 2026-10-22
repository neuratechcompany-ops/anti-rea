import { createHash } from "node:crypto";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function decrypt(base64, seed) {
  const bytes = Buffer.from(base64, "base64");
  let state = seed >>> 0 || 0x9e3779b9;
  for (let index = 0; index < bytes.length; index += 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    bytes[index] ^= state & 0xff;
  }
  return bytes;
}

export function unpackVmPayloads(source) {
  const payloadPattern = /Buffer\.from\(\s*(["'])([A-Za-z0-9+/=]{32,})\1\s*,\s*(["'])base64\3\s*\)/g;
  const results = [];
  for (const match of source.matchAll(payloadPattern)) {
    const tail = source.slice(match.index + match[0].length, match.index + match[0].length + 2500);
    const seedMatch = tail.match(/(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*(\d{1,10})\s*\|\|\s*2654435769/);
    if (!seedMatch) continue;
    const seed = Number(seedMatch[1]);
    if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) continue;
    const plaintext = decrypt(match[2], seed);
    try {
      const program = JSON.parse(plaintext.toString("utf8"));
      if (!program || !/^[a-f0-9]{64}$/.test(program.d ?? "") || !Array.isArray(program.c) || !Array.isArray(program.i) || program.i.some((item) => !Array.isArray(item) || item.length !== 2)) continue;
      results.push({
        functionId: program.d,
        seed,
        encryptedSha256: sha256(Buffer.from(match[2], "base64")),
        plaintextSha256: sha256(plaintext),
        constants: program.c,
        instructions: program.i.length,
      });
    } catch {
      // Candidate was not an Anti-REA VM payload.
    }
  }
  return results;
}

export function recognizeVmEnvelopes(source) {
  const payloadPattern = /Buffer\.from\(\s*(["'])([A-Za-z0-9+/=]{32,})\1\s*,\s*(["'])base64\3\s*\)/g;
  return [...source.matchAll(payloadPattern)].map((match) => sha256(Buffer.from(match[2], "base64")));
}

export function recognizeVmFunctionIds(source) {
  return [...new Set([...source.matchAll(/ARVMID:([a-f0-9]{64})/g)].map((match) => match[1]))].sort();
}

export function recoverCanaries(programs, canaries) {
  const corpus = programs.map((item) => JSON.stringify(item.constants)).join("\n");
  return canaries.filter((item) => corpus.includes(item));
}
