import { timingSafeEqual } from "node:crypto";
import { chacha20 } from "./chacha20.mjs";

function littleEndianBigInt(bytes) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]);
  return value;
}

function writeLittleEndian(value, length) {
  const output = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) {
    output[index] = Number(value & 255n);
    value >>= 8n;
  }
  return output;
}

function pad16(bytes) {
  const remainder = bytes.length % 16;
  return remainder === 0 ? Buffer.alloc(0) : Buffer.alloc(16 - remainder);
}

function uint64le(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("AEAD input is too large");
  return writeLittleEndian(BigInt(value), 8);
}

export function poly1305(message, oneTimeKey) {
  if (!(oneTimeKey instanceof Uint8Array) || oneTimeKey.byteLength !== 32) throw new Error("Poly1305 key must contain 32 bytes");
  const r = littleEndianBigInt(oneTimeKey.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const s = littleEndianBigInt(oneTimeKey.subarray(16, 32));
  const prime = (1n << 130n) - 5n;
  let accumulator = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const block = message.subarray(offset, Math.min(offset + 16, message.length));
    const n = littleEndianBigInt(block) + (1n << BigInt(block.length * 8));
    accumulator = ((accumulator + n) * r) % prime;
  }
  return writeLittleEndian((accumulator + s) & ((1n << 128n) - 1n), 16);
}

function macData(aad, ciphertext) {
  return Buffer.concat([Buffer.from(aad), pad16(aad), Buffer.from(ciphertext), pad16(ciphertext), uint64le(aad.length), uint64le(ciphertext.length)]);
}

export function chacha20Poly1305Seal(plaintext, key, nonce, aad = Buffer.alloc(0)) {
  const oneTimeKey = chacha20(Buffer.alloc(32), key, nonce, 0);
  const ciphertext = chacha20(Buffer.from(plaintext), key, nonce, 1);
  const tag = poly1305(macData(Buffer.from(aad), ciphertext), oneTimeKey);
  oneTimeKey.fill(0);
  return { ciphertext, tag };
}

export function chacha20Poly1305Open(ciphertext, tag, key, nonce, aad = Buffer.alloc(0)) {
  if (!(tag instanceof Uint8Array) || tag.byteLength !== 16) throw new Error("ChaCha20-Poly1305 tag must contain 16 bytes");
  const oneTimeKey = chacha20(Buffer.alloc(32), key, nonce, 0);
  const expected = poly1305(macData(Buffer.from(aad), Buffer.from(ciphertext)), oneTimeKey);
  oneTimeKey.fill(0);
  if (!timingSafeEqual(expected, Buffer.from(tag))) throw new Error("ChaCha20-Poly1305 authentication failed");
  return chacha20(Buffer.from(ciphertext), key, nonce, 1);
}
