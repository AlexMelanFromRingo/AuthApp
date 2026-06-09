// Динамічне усічення — дзеркало Kotlin-ядра (contracts/crypto-core.md).
// Стандартні алгоритми: строго RFC 4226 (молодший нібл останнього байта).
// Розширені: узагальнене правило offset = останній байт mod (L−4), що
// рівномірно покриває весь MAC; для 9–10 цифр беруться 8 байтів (63 біти).
import { ALGORITHMS } from './mac.js';

/**
 * @param {string} alg канонічний ідентифікатор алгоритму
 * @param {Uint8Array} mac
 * @param {number} digits 6..10
 * @returns {{offset: number, code: string}}
 */
export function truncate(alg, mac, digits) {
  if (digits < 6 || digits > 10) {
    throw new Error(`Довжина коду має бути від 6 до 10 цифр, отримано ${digits}`);
  }
  const meta = ALGORITHMS[alg];
  if (!meta) throw new Error(`Невідомий алгоритм: ${alg}`);

  const L = mac.length;
  const lastByte = mac[L - 1];
  let offset, value;

  if (!meta.extended) {
    if (digits > 8) throw new Error('Стандартні алгоритми обмежені 8 цифрами (RFC 4226)');
    offset = lastByte & 0x0f;
    value = read31(mac, offset);
  } else if (digits <= 8) {
    offset = lastByte % (L - 4);
    value = read31(mac, offset);
  } else {
    offset = lastByte % (L - 8);
    value = read63(mac, offset);
  }

  const code = (value % 10n ** BigInt(digits)).toString().padStart(digits, '0');
  return { offset, code };
}

function read31(mac, offset) {
  let v = 0n;
  for (let i = 0; i < 4; i++) v = (v << 8n) | BigInt(mac[offset + i]);
  return v & 0x7fffffffn;
}

function read63(mac, offset) {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(mac[offset + i]);
  return v & 0x7fffffffffffffffn;
}
