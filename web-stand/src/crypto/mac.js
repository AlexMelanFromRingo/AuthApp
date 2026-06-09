// MAC-фабрика — дзеркало Kotlin-ядра (contracts/crypto-core.md).
// Усі примітиви — з аудитованої бібліотеки @noble/hashes; самописних
// реалізацій хеш-функцій немає (Конституція, Принцип II).
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { blake2b, blake2s } from '@noble/hashes/blake2.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { hmac } from '@noble/hashes/hmac.js';

/** Спільний словник алгоритмів (data-model.md): id → властивості. */
export const ALGORITHMS = {
  'SHA1':        { macLength: 20, extended: false },
  'SHA256':      { macLength: 32, extended: false },
  'SHA512':      { macLength: 64, extended: false },
  'SHA3-256':    { macLength: 32, extended: true },
  'BLAKE2S-256': { macLength: 32, extended: true },
  'BLAKE2B-512': { macLength: 64, extended: true },
  'BLAKE3-256':  { macLength: 32, extended: true },
};

/**
 * Обчислення MAC: HMAC для SHA-сімейства, нативний keyed-режим для BLAKE.
 * Конвенція довгого ключа (FR-008): секрет, що не вміщається в keyed-режим,
 * попередньо хешується тим самим алгоритмом.
 * @param {string} alg канонічний ідентифікатор алгоритму
 * @param {Uint8Array} key секрет
 * @param {Uint8Array} data повідомлення
 * @returns {Uint8Array}
 */
export function computeMac(alg, key, data) {
  switch (alg) {
    case 'SHA1':   return hmac(sha1, key, data);
    case 'SHA256': return hmac(sha256, key, data);
    case 'SHA512': return hmac(sha512, key, data);
    case 'SHA3-256': return hmac(sha3_256, key, data);
    case 'BLAKE2S-256':
      return blake2s(data, { key: key.length > 32 ? blake2s(key) : key });
    case 'BLAKE2B-512':
      return blake2b(data, { key: key.length > 64 ? blake2b(key) : key });
    case 'BLAKE3-256':
      return blake3(data, { key: key.length !== 32 ? blake3(key) : key });
    default:
      throw new Error(`Невідомий алгоритм: ${alg}`);
  }
}
