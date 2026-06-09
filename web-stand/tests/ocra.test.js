// Векторні тести OCRA (SC-002): ті самі спільні вектори, що й у Kotlin,
// включно з офіційними RFC 6287 Appendix C.1.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseSuite, computeResponse, verifyResponse } from '../src/crypto/ocra.js';
import { hexToBytes } from '../src/crypto/base32.js';

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), '../../shared/test-vectors');
const { cases } = JSON.parse(readFileSync(join(vectorsDir, 'ocra.json'), 'utf8'));

describe('вектори OCRA (спільні з Kotlin-ядром)', () => {
  it('файл не порожній', () => expect(cases.length).toBeGreaterThan(0));
  for (const c of cases) {
    it(`${c.suite} q=${c.q}`, () => {
      const suite = parseSuite(c.suite);
      expect(computeResponse(suite, hexToBytes(c.keyHex), c.q, c.time ?? null)).toBe(c.expected);
    });
  }
});

describe('верифікація OCRA', () => {
  const suite = parseSuite('OCRA-1:HOTP-SHA256-8:QN08-T30S');
  const key = hexToBytes('3132333435363738393031323334353637383930313233343536373839303132');
  const time = 1111111111;
  const valid = computeResponse(suite, key, '11111111', time);

  it('приймає зсув годинника ±1 крок', () => {
    expect(verifyResponse(suite, key, '11111111', valid, time + 30)).toBe(true);
    expect(verifyResponse(suite, key, '11111111', valid, time - 30)).toBe(true);
  });
  it('відхиляє понад вікно і підробку', () => {
    expect(verifyResponse(suite, key, '11111111', valid, time + 120)).toBe(false);
    expect(verifyResponse(suite, key, '11111111', '00000000', time)).toBe(false);
  });
  it('відхиляє непідтримувані профілі', () => {
    expect(() => parseSuite('OCRA-1:HOTP-SHA256-8:C-QN08')).toThrow();
    expect(() => parseSuite('OCRA-1:HOTP-SHA256-8:QA10')).toThrow();
  });
});
