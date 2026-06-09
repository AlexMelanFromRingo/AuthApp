// TOTP за RFC 6238 — дзеркало Kotlin-ядра.
import { computeMac } from './mac.js';
import { truncate } from './truncation.js';

/**
 * @param {string} alg канонічний ідентифікатор алгоритму
 * @param {Uint8Array} secret
 * @param {number} timeSeconds unix-час у секундах
 * @param {number} period 15..120
 * @param {number} digits 6..10
 * @returns {string} код із провідними нулями
 */
export function generateTotp(alg, secret, timeSeconds, period = 30, digits = 6) {
  if (period < 15 || period > 120) {
    throw new Error(`Період має бути від 15 до 120 секунд, отримано ${period}`);
  }
  if (!secret || secret.length === 0) throw new Error('Секрет не може бути порожнім');

  const counter = BigInt(Math.floor(timeSeconds / period));
  const counterBytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  return truncate(alg, computeMac(alg, secret, counterBytes), digits).code;
}

/**
 * Валідація коду з вікном ±window періодів (FR-019/FR-022 специфікації:
 * стенд приймає коди в межах ±1 періоду для компенсації зсуву годинника).
 */
export function verifyTotp(alg, secret, code, timeSeconds, period = 30, digits = 6, window = 1) {
  const normalized = code.replace(/\s+/g, '');
  for (let step = -window; step <= window; step++) {
    if (generateTotp(alg, secret, timeSeconds + step * period, period, digits) === normalized) {
      return true;
    }
  }
  return false;
}
