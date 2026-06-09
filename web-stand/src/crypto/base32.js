// Base32 за RFC 4648 без паддінгу — дзеркало Kotlin-ядра.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** @param {Uint8Array} data */
export function base32Encode(data) {
  let out = '';
  let buffer = 0n, bits = 0;
  for (const byte of data) {
    buffer = (buffer << 8n) | BigInt(byte);
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[Number((buffer >> BigInt(bits)) & 0x1fn)];
    }
  }
  if (bits > 0) out += ALPHABET[Number((buffer << BigInt(5 - bits)) & 0x1fn)];
  return out;
}

/** @param {string} text @returns {Uint8Array} */
export function base32Decode(text) {
  const clean = text.toUpperCase().replace(/[\s=-]/g, '');
  const out = [];
  let buffer = 0n, bits = 0;
  for (const c of clean) {
    const value = ALPHABET.indexOf(c);
    if (value < 0) throw new Error(`Недопустимий символ Base32: «${c}»`);
    buffer = (buffer << 5n) | BigInt(value);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push(Number((buffer >> BigInt(bits)) & 0xffn));
    }
  }
  return new Uint8Array(out);
}

/** @param {string} hex @returns {Uint8Array} */
export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
