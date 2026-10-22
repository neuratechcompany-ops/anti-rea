import assert from "node:assert/strict";
import test from "node:test";
import { recognizeVmEnvelopes, recognizeVmFunctionIds, recoverCanaries, unpackVmPayloads } from "../scripts/unpack-vm-payload.mjs";

function encrypt(value, seed) {
  const bytes = Buffer.from(JSON.stringify(value));
  let state = seed >>> 0 || 0x9e3779b9;
  for (let index = 0; index < bytes.length; index += 1) {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    bytes[index] ^= state & 255;
  }
  return bytes.toString("base64");
}

test("public-deobfuscator follow-up statically unpacks the current VM envelope", () => {
  const seed = 3595797435;
  const payload = { d: "a".repeat(64), c: ["ENTERPRISE_MARGIN_42", "other"], i: [[17, 0], [24, 0]] };
  const encoded = encrypt(payload, seed);
  const source = `var d="ARVMID:${"a".repeat(64)}",q=Buffer.from("${encoded}","base64");var x=${seed}||2654435769;`;
  const programs = unpackVmPayloads(source);
  assert.equal(recognizeVmEnvelopes(source).length, 1);
  assert.equal(programs.length, 1);
  assert.equal(programs[0].instructions, 2);
  assert.equal(programs[0].functionId, "a".repeat(64));
  assert.deepEqual(recognizeVmFunctionIds(source), ["a".repeat(64)]);
  assert.deepEqual(recoverCanaries(programs, ["ENTERPRISE_MARGIN_42", "absent"]), ["ENTERPRISE_MARGIN_42"]);
});

test("unpacker does not treat arbitrary base64 as a valid VM payload", () => {
  const source = `var q=Buffer.from("${Buffer.from("not a program").toString("base64")}","base64");var x=7||2654435769;`;
  assert.deepEqual(unpackVmPayloads(source), []);
});
