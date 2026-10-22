import assert from "node:assert/strict";
import test from "node:test";
import { chacha20 } from "../scripts/chacha20.mjs";
import { chacha20Poly1305Open, chacha20Poly1305Seal } from "../scripts/chacha20-poly1305.mjs";

test("ChaCha20 matches the RFC 8439 section 2.4.2 vector", () => {
  const key = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
  const nonce = Buffer.from("000000000000004a00000000", "hex");
  const plaintext = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";
  assert.equal(chacha20(plaintext, key, nonce, 1).toString("hex"), expected);
  assert.deepEqual(chacha20(Buffer.from(expected, "hex"), key, nonce, 1), plaintext);
});

test("ChaCha20 rejects malformed key and nonce sizes", () => {
  assert.throws(() => chacha20(Buffer.alloc(1), Buffer.alloc(31), Buffer.alloc(12)), /key/);
  assert.throws(() => chacha20(Buffer.alloc(1), Buffer.alloc(32), Buffer.alloc(11)), /nonce/);
});

test("ChaCha20-Poly1305 matches RFC 8439 section 2.8.2 and rejects tampering", () => {
  const key = Buffer.from("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "hex");
  const nonce = Buffer.from("070000004041424344454647", "hex");
  const aad = Buffer.from("50515253c0c1c2c3c4c5c6c7", "hex");
  const plaintext = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const expectedCiphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
  const sealed = chacha20Poly1305Seal(plaintext, key, nonce, aad);
  assert.equal(sealed.ciphertext.toString("hex"), expectedCiphertext);
  assert.equal(sealed.tag.toString("hex"), "1ae10b594f09e26a7e902ecbd0600691");
  assert.deepEqual(chacha20Poly1305Open(sealed.ciphertext, sealed.tag, key, nonce, aad), plaintext);
  const modified = Buffer.from(sealed.ciphertext); modified[0] ^= 1;
  assert.throws(() => chacha20Poly1305Open(modified, sealed.tag, key, nonce, aad), /authentication failed/);
});
