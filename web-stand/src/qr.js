// Генерація QR-кодів (обгортка пакета qrcode) і побудова URI за контрактом
// contracts/qr-uri-schemes.md.
import QRCode from 'qrcode';
import { ALGORITHMS } from './crypto/mac.js';

/** Малює QR у canvas. Рівень корекції M (R6). */
export async function drawQr(canvas, text) {
  await QRCode.toCanvas(canvas, text, { errorCorrectionLevel: 'M', width: 260, margin: 2 });
}

/**
 * URI провіжинингу TOTP: стандартні алгоритми — otpauth:// (сумісність зі
 * сторонніми додатками), розширені — authapp://totp (v=1).
 */
export function buildTotpUri({ issuer, account, secretBase32, alg, digits, period }) {
  const meta = ALGORITHMS[alg];
  if (!meta) throw new Error(`Невідомий алгоритм: ${alg}`);
  if (!meta.extended && digits <= 8) {
    const label = encodeURIComponent(`${issuer}:${account}`);
    return `otpauth://totp/${label}?secret=${secretBase32}` +
      `&issuer=${encodeURIComponent(issuer)}&algorithm=${alg}&digits=${digits}&period=${period}`;
  }
  return `authapp://totp?v=1&secret=${secretBase32}&alg=${alg}&digits=${digits}` +
    `&period=${period}&issuer=${encodeURIComponent(issuer)}&account=${encodeURIComponent(account)}`;
}

/** URI провіжинингу OCRA-токена. */
export function buildOcraTokenUri({ issuer, account, secretBase32, suite }) {
  return `authapp://ocra-token?v=1&secret=${secretBase32}&suite=${encodeURIComponent(suite)}` +
    `&issuer=${encodeURIComponent(issuer)}&account=${encodeURIComponent(account)}`;
}

/** URI OCRA-виклику (FR-014): cid, строк дії 120 с; опційно C/S/режим підпису. */
export function buildChallengeUri({ suite, q, cid, label, counter, sessionB64, mode }) {
  let uri = `authapp://ocra-challenge?v=1&suite=${encodeURIComponent(suite)}` +
    `&q=${encodeURIComponent(q)}&cid=${cid}&exp=120&label=${encodeURIComponent(label ?? '')}`;
  if (counter != null) uri += `&c=${counter}`;
  if (sessionB64) uri += `&s=${sessionB64}`;
  if (mode) uri += `&mode=${mode}`;
  return uri;
}

/** URI взаємної автентифікації: клієнт верифікує відгук сервера і відповідає. */
export function buildMutualUri({ clientSuite, serverSuite, qc, qs, serverResponse, cid, label }) {
  return `authapp://ocra-mutual?v=1&csuite=${encodeURIComponent(clientSuite)}` +
    `&ssuite=${encodeURIComponent(serverSuite)}&qc=${encodeURIComponent(qc)}` +
    `&qs=${encodeURIComponent(qs)}&srv=${serverResponse}&cid=${cid}&exp=120` +
    `&label=${encodeURIComponent(label ?? '')}`;
}
