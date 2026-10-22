function rotateLeft(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function quarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0; state[d] = rotateLeft(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0; state[b] = rotateLeft(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0; state[d] = rotateLeft(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0; state[b] = rotateLeft(state[b] ^ state[c], 7);
}

export function chacha20(value, key, nonce, initialCounter = 1) {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) throw new Error("ChaCha20 key must contain 32 bytes");
  if (!(nonce instanceof Uint8Array) || nonce.byteLength !== 12) throw new Error("ChaCha20 nonce must contain 12 bytes");
  if (!Number.isSafeInteger(initialCounter) || initialCounter < 0 || initialCounter > 0xffffffff) throw new Error("ChaCha20 counter is invalid");
  const output = Buffer.from(value);
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  for (let offset = 0, counter = initialCounter; offset < output.length; offset += 64, counter += 1) {
    if (counter > 0xffffffff) throw new Error("ChaCha20 counter overflow");
    const initial = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    for (let index = 0; index < 8; index += 1) initial.push(keyView.getUint32(index * 4, true));
    initial.push(counter >>> 0, nonceView.getUint32(0, true), nonceView.getUint32(4, true), nonceView.getUint32(8, true));
    const state = [...initial];
    for (let round = 0; round < 10; round += 1) {
      quarterRound(state, 0, 4, 8, 12); quarterRound(state, 1, 5, 9, 13); quarterRound(state, 2, 6, 10, 14); quarterRound(state, 3, 7, 11, 15);
      quarterRound(state, 0, 5, 10, 15); quarterRound(state, 1, 6, 11, 12); quarterRound(state, 2, 7, 8, 13); quarterRound(state, 3, 4, 9, 14);
    }
    const block = Buffer.alloc(64);
    for (let index = 0; index < 16; index += 1) block.writeUInt32LE((state[index] + initial[index]) >>> 0, index * 4);
    for (let index = 0; index < Math.min(64, output.length - offset); index += 1) output[offset + index] ^= block[index];
  }
  return output;
}
