// Векторні тести стенду (SC-001): ті самі спільні вектори, що й у Kotlin.
// 100% кейсів мають проходити без винятків і фільтрів.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { generateTotp } from '../src/crypto/totp.js';
import { truncate } from '../src/crypto/truncation.js';
import { hexToBytes, base32Decode, base32Encode } from '../src/crypto/base32.js';

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), '../../shared/test-vectors');
const load = (name) => JSON.parse(readFileSync(join(vectorsDir, name), 'utf8'));

describe('вектори TOTP (спільні з Kotlin-ядром)', () => {
  const { cases } = load('totp.json');
  it('файл не порожній', () => expect(cases.length).toBeGreaterThan(0));
  for (const c of cases) {
    it(`${c.alg} t=${c.time} digits=${c.digits}`, () => {
      const actual = generateTotp(c.alg, hexToBytes(c.secretHex), c.time, c.period, c.digits);
      expect(actual).toBe(c.expected);
    });
  }
});

describe('вектори динамічного усічення', () => {
  const { cases } = load('truncation.json');
  for (const c of cases) {
    it(`${c.rule} ${c.alg} digits=${c.digits}`, () => {
      const { offset, code } = truncate(c.alg, hexToBytes(c.macHex), c.digits);
      expect(offset).toBe(c.expectedOffset);
      expect(code).toBe(c.expected);
    });
  }
});

describe('Base32', () => {
  it('кодування і декодування симетричні', () => {
    const data = new TextEncoder().encode('12345678901234567890');
    const encoded = base32Encode(data);
    expect(encoded).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(base32Decode(encoded)).toEqual(data);
    expect(base32Decode('gezd gnbv gy3t qojq gezd gnbv gy3t qojq')).toEqual(data);
  });
});
