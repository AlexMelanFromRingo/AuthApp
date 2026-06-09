// OCRA за RFC 6287 — дзеркало Kotlin-ядра (профілі QN08, опціональний T).
import { computeMac } from './mac.js';
import { truncate } from './truncation.js';

/**
 * Розбір OCRA-профілю. Лічильник (C), PIN (P) і сесія (S) — поза межами
 * версії (FR-013).
 * @param {string} raw напр. "OCRA-1:HOTP-SHA256-8:QN08-T30S"
 */
export function parseSuite(raw) {
  const parts = raw.split(':');
  if (parts.length !== 3 || parts[0] !== 'OCRA-1') {
    throw new Error(`Непідтримуваний OCRA-профіль: «${raw}»`);
  }
  const crypto = /^HOTP-(SHA1|SHA256|SHA512)-([68])$/.exec(parts[1]);
  if (!crypto) {
    throw new Error(`Підтримуються лише HOTP-SHA1/SHA256/SHA512 із 6 або 8 цифрами, отримано «${parts[1]}»`);
  }
  const data = /^QN08(?:-T(30S|1M))?$/.exec(parts[2]);
  if (!data) {
    throw new Error(`Підтримуються лише виклики QN08 з опціональною часовою прив'язкою, отримано «${parts[2]}»`);
  }
  return {
    raw,
    algorithm: crypto[1],
    digits: Number(crypto[2]),
    timeStepSeconds: data[1] === '30S' ? 30 : data[1] === '1M' ? 60 : null,
  };
}

/**
 * Відгук на виклик: DataInput = suite ‖ 0x00 ‖ Q(128 Б) [‖ T(8 Б BE)].
 * @param {ReturnType<typeof parseSuite>} suite
 * @param {Uint8Array} key
 * @param {string} question 8 цифр (QN08)
 * @param {number|null} timeSeconds unix-час для часових профілів
 */
export function computeResponse(suite, key, question, timeSeconds = null) {
  if (!/^\d{8}$/.test(question)) {
    throw new Error('Виклик має складатися рівно з 8 цифр (профіль QN08)');
  }
  const encoder = new TextEncoder();
  const parts = [encoder.encode(suite.raw), new Uint8Array([0]), encodeQuestion(question)];

  if (suite.timeStepSeconds !== null) {
    if (timeSeconds === null) throw new Error(`Часовий профіль ${suite.raw} потребує поточного часу`);
    let t = BigInt(Math.floor(timeSeconds / suite.timeStepSeconds));
    const tBytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) { tBytes[i] = Number(t & 0xffn); t >>= 8n; }
    parts.push(tBytes);
  }

  const total = parts.reduce((n, p) => n + p.length, 0);
  const data = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) { data.set(p, pos); pos += p.length; }

  return truncate(suite.algorithm, computeMac(suite.algorithm, key, data), suite.digits).code;
}

/** Валідація відгуку: для часових профілів вікно ±1 крок (FR-015). */
export function verifyResponse(suite, key, question, response, timeSeconds = null) {
  const shifts = suite.timeStepSeconds === null
    ? [0]
    : [-suite.timeStepSeconds, 0, suite.timeStepSeconds];
  return shifts.some((shift) =>
    computeResponse(suite, key, question, timeSeconds === null ? null : timeSeconds + shift) === response.trim());
}

// Q: число → hex (доповнений до парної довжини) → байти, вліво, до 128 Б
function encodeQuestion(question) {
  let hex = BigInt(question).toString(16);
  if (hex.length % 2) hex += '0';
  const out = new Uint8Array(128);
  for (let i = 0; i < hex.length / 2; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
