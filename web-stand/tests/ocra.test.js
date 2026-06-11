// Векторні тести OCRA (SC-002): повний набір RFC 6287 Appendix C —
// односторонні (C, PSHA1, T), взаємна автентифікація, підпис транзакцій.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseSuite, computeResponse, verifyResponse, hashPin } from '../src/crypto/ocra.js';
import { hexToBytes } from '../src/crypto/base32.js';

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), '../../shared/test-vectors');
const { cases } = JSON.parse(readFileSync(join(vectorsDir, 'ocra.json'), 'utf8'));

describe('вектори OCRA (спільні з Kotlin-ядром)', () => {
  it('покриття: ≥70 кейсів', () => expect(cases.length).toBeGreaterThanOrEqual(70));
  cases.forEach((c, index) => {
    it(`#${index} ${c.suite} q=${c.q}`, () => {
      const suite = parseSuite(c.suite);
      const actual = computeResponse(suite, hexToBytes(c.keyHex), {
        question: c.q,
        counter: c.counter ?? null,
        pinHash: c.pinHashHex ? hexToBytes(c.pinHashHex) : null,
        sessionInfo: c.sessionHex ? hexToBytes(c.sessionHex) : null,
        timeSeconds: c.time ?? null,
      });
      expect(actual).toBe(c.expected);
    });
  });
});

describe('верифікація OCRA', () => {
  const suite = parseSuite('OCRA-1:HOTP-SHA256-8:QN08-T30S');
  const key = hexToBytes('3132333435363738393031323334353637383930313233343536373839303132');
  const time = 1111111111;
  const inputs = { question: '11111111', timeSeconds: time };
  const valid = computeResponse(suite, key, inputs);

  it('приймає зсув годинника ±1 крок', () => {
    expect(verifyResponse(suite, key, { ...inputs, timeSeconds: time + 30 }, valid)).toBe(true);
    expect(verifyResponse(suite, key, { ...inputs, timeSeconds: time - 30 }, valid)).toBe(true);
  });
  it('відхиляє понад вікно і підробку', () => {
    expect(verifyResponse(suite, key, { ...inputs, timeSeconds: time + 120 }, valid)).toBe(false);
    expect(verifyResponse(suite, key, inputs, '00000000')).toBe(false);
  });
  it('хеш PIN збігається з еталоном RFC', () => {
    expect(Buffer.from(hashPin('1234', 'SHA1')).toString('hex'))
      .toBe('7110eda4d09e062aa5e4a390b0a572ac0d2c0220');
  });
  it('парсер: повна граматика і відмови', () => {
    const full = parseSuite('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1-S064-T1M');
    expect(full.useCounter).toBe(true);
    expect(full.pinHashAlgorithm).toBe('SHA1');
    expect(full.sessionLength).toBe(64);
    expect(full.timeStepSeconds).toBe(60);
    expect(() => parseSuite('OCRA-1:HOTP-SHA256-8:QN08-X064')).toThrow();
    expect(() => parseSuite('OCRA-1:HOTP-SHA256-8:C')).toThrow();
  });
});
