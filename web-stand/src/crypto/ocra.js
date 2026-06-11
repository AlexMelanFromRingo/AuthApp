// OCRA за RFC 6287 — дзеркало Kotlin-ядра. Повна граматика профілю (FR-027):
// [C-]Q{N|A|H}{04..64}[-PSHA{1|256|512}][-S{nnn}][-T{n}{S|M|H}]
// DataInput = suite ‖ 0x00 ‖ [C 8Б] ‖ Q(128Б) ‖ [P hash] ‖ [S nnn] ‖ [T 8Б]
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { computeMac, ALGORITHMS } from './mac.js';
import { truncate } from './truncation.js';

/** Розбір OCRA-профілю; невідомі компоненти → помилка. */
export function parseSuite(raw) {
  const parts = raw.split(':');
  if (parts.length !== 3 || parts[0] !== 'OCRA-1') {
    throw new Error(`Непідтримуваний OCRA-профіль: «${raw}»`);
  }
  const crypto = /^HOTP-(SHA1|SHA256|SHA512)-([68])$/.exec(parts[1]);
  if (!crypto) {
    throw new Error(`Підтримуються лише HOTP-SHA1/SHA256/SHA512 із 6 або 8 цифрами, отримано «${parts[1]}»`);
  }

  let components = parts[2].split('-');
  let useCounter = false;
  if (components[0] === 'C') {
    useCounter = true;
    components = components.slice(1);
  }

  const question = /^Q([NAH])(\d{2})$/.exec(components[0] ?? '');
  if (!question) throw new Error(`OCRA-профіль має містити виклик Q: «${parts[2]}»`);
  const questionLength = Number(question[2]);
  if (questionLength < 4 || questionLength > 64) {
    throw new Error(`Довжина виклику має бути 04..64, отримано ${questionLength}`);
  }

  let pinHashAlgorithm = null;
  let sessionLength = null;
  let timeStepSeconds = null;
  for (const component of components.slice(1)) {
    let m;
    if ((m = /^PSHA(1|256|512)$/.exec(component))) {
      pinHashAlgorithm = `SHA${m[1]}`;
    } else if ((m = /^S(\d{3})$/.exec(component))) {
      sessionLength = Number(m[1]);
    } else if ((m = /^T(\d{1,2})([SMH])$/.exec(component))) {
      timeStepSeconds = Number(m[1]) * { S: 1, M: 60, H: 3600 }[m[2]];
    } else {
      throw new Error(`Невідомий компонент OCRA-профілю: «${component}»`);
    }
  }

  return {
    raw,
    algorithm: crypto[1],
    digits: Number(crypto[2]),
    useCounter,
    questionFormat: question[1], // 'N' | 'A' | 'H'
    questionLength,
    pinHashAlgorithm,
    sessionLength,
    timeStepSeconds,
  };
}

/**
 * Відгук на виклик.
 * @param {ReturnType<typeof parseSuite>} suite
 * @param {Uint8Array} key
 * @param {{question: string, counter?: number|null, pinHash?: Uint8Array|null,
 *          sessionInfo?: Uint8Array|null, timeSeconds?: number|null}} inputs
 */
export function computeResponse(suite, key, inputs) {
  const encoder = new TextEncoder();
  const parts = [encoder.encode(suite.raw), new Uint8Array([0])];

  if (suite.useCounter) {
    if (inputs.counter == null) throw new Error(`Профіль ${suite.raw} потребує лічильника`);
    parts.push(to8Bytes(BigInt(inputs.counter)));
  }

  parts.push(encodeQuestion(suite, inputs.question));

  if (suite.pinHashAlgorithm) {
    const expectedLen = ALGORITHMS[suite.pinHashAlgorithm].macLength;
    if (!inputs.pinHash) throw new Error(`Профіль ${suite.raw} потребує PIN-коду`);
    if (inputs.pinHash.length !== expectedLen) {
      throw new Error(`Хеш PIN має бути ${expectedLen} байтів для ${suite.pinHashAlgorithm}`);
    }
    parts.push(inputs.pinHash);
  }

  if (suite.sessionLength != null) {
    if (!inputs.sessionInfo) throw new Error(`Профіль ${suite.raw} потребує сесійних даних`);
    const session = new Uint8Array(suite.sessionLength);
    session.set(inputs.sessionInfo.slice(0, suite.sessionLength));
    parts.push(session);
  }

  if (suite.timeStepSeconds != null) {
    if (inputs.timeSeconds == null) throw new Error(`Часовий профіль ${suite.raw} потребує поточного часу`);
    parts.push(to8Bytes(BigInt(Math.floor(inputs.timeSeconds / suite.timeStepSeconds))));
  }

  const total = parts.reduce((n, p) => n + p.length, 0);
  const data = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) { data.set(p, pos); pos += p.length; }

  return truncate(suite.algorithm, computeMac(suite.algorithm, key, data), suite.digits).code;
}

/** Валідація відгуку: для часових профілів вікно ±1 крок (FR-015). */
export function verifyResponse(suite, key, inputs, response) {
  const shifts = suite.timeStepSeconds == null
    ? [0]
    : [-suite.timeStepSeconds, 0, suite.timeStepSeconds];
  return shifts.some((shift) => computeResponse(suite, key, {
    ...inputs,
    timeSeconds: inputs.timeSeconds == null ? null : inputs.timeSeconds + shift,
  }) === response.trim());
}

/** Хеш PIN для P-компонента. @param {string} pin @param {string} alg */
export function hashPin(pin, alg) {
  const bytes = new TextEncoder().encode(pin);
  switch (alg) {
    case 'SHA1': return sha1(bytes);
    case 'SHA256': return sha256(bytes);
    case 'SHA512': return sha512(bytes);
    default: throw new Error('PIN-хеш підтримує лише SHA-1/256/512');
  }
}

function encodeQuestion(suite, question) {
  let qBytes;
  if (suite.questionFormat === 'N') {
    if (!/^\d+$/.test(question)) throw new Error('Числовий виклик має складатися лише з цифр');
    let hex = BigInt(question).toString(16);
    if (hex.length % 2) hex += '0';
    qBytes = hexBytes(hex);
  } else if (suite.questionFormat === 'A') {
    qBytes = new TextEncoder().encode(question);
  } else {
    const hex = question.length % 2 ? question + '0' : question;
    if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('Шістнадцятковий виклик містить недопустимі символи');
    qBytes = hexBytes(hex);
  }
  if (qBytes.length < 1 || qBytes.length > 128) throw new Error('Виклик задовгий: максимум 128 байтів');
  const out = new Uint8Array(128);
  out.set(qBytes);
  return out;
}

function hexBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function to8Bytes(value) {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
