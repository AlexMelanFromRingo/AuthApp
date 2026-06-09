# Контракт: криптографічне ядро (Kotlin ↔ JS еквівалентність)

**Версія**: 1 | **Реалізації**: `android-app/core-crypto` (Kotlin/JVM,
Bouncy Castle) та `web-stand/src/crypto/` (@noble/hashes). Обидві MUST
давати побітово ідентичні результати на спільних тестових векторах.

## MAC-фабрика

| Алгоритм | Конструкція | Примітка |
|----------|-------------|----------|
| SHA1, SHA256, SHA512 | HMAC | стандарт RFC 2104 |
| SHA3-256 | HMAC | block size 136 Б |
| BLAKE2S-256 | keyed BLAKE2s | ключ ≤32 Б; довший → BLAKE2s(secret) |
| BLAKE2B-512 | keyed BLAKE2b | ключ ≤64 Б; довший → BLAKE2b(secret) |
| BLAKE3-256 | keyed BLAKE3 | ключ рівно 32 Б; інший розмір → BLAKE3(secret) |

## Динамічне усічення

Вхід: `mac: байти довжини L`, `digits: 6..10`. Вихід: рядок із `digits`
цифр із провідними нулями.

**Стандартні алгоритми (SHA1/256/512)** — строго RFC 4226:

```
offset = mac[L-1] & 0x0F
P = (mac[offset..offset+3] як big-endian uint32) & 0x7FFFFFFF
code = P mod 10^digits          // digits ≤ 8
```

**Розширені алгоритми** — узагальнене правило (FR-009):

```
якщо digits ≤ 8:
    offset = mac[L-1] mod (L-4)            // 0..L-5, вікно не торкає mac[L-1]
    P = (mac[offset..offset+3] BE uint32) & 0x7FFFFFFF      // 31 біт
інакше (digits 9..10):
    offset = mac[L-1] mod (L-8)            // 0..L-9
    P = (mac[offset..offset+7] BE uint64) & 0x7FFFFFFFFFFFFFFF  // 63 біти
code = P mod 10^digits
```

Інваріант: для L=20 і digits≤8 узагальнене правило тотожне RFC 4226
(mod 16 = молодший нібл) — перевіряється окремим тестом.

## TOTP

```
T = floor((unix_time - T0) / period),  T0 = 0
code = усічення(MAC(secret, T як 8 Б big-endian), digits)
```

## OCRA (RFC 6287, підмножина)

Див. contracts/qr-uri-schemes.md §3. MAC і усічення — ті самі, що вище
(OCRA використовує лише HMAC-SHA1/256/512 за профілем).

## Тестові вектори (спільний артефакт)

Розташування: `shared/test-vectors/*.json`. Генератор:
`shared/test-vectors/generate.py` (Python: hashlib + пакет blake3) —
незалежна третя реалізація (R7).

Формати:

```json
// totp.json
{"cases":[{"alg":"BLAKE3-256","secretHex":"...","time":59,"period":30,
           "digits":9,"expected":"012345678"}]}
// truncation.json
{"cases":[{"alg":"BLAKE2B-512","macHex":"...","digits":10,
           "expectedOffset":17,"expected":"0123456789"}]}
// ocra.json — вектори RFC 6287 Appendix C + власні для T-профілів
{"cases":[{"suite":"OCRA-1:HOTP-SHA1-6:QN08","keyHex":"...","q":"00000000",
           "expected":"237653"}]}
```

Вимога (FR-010, SC-001/002): 100% кейсів проходять у Kotlin-тестах
(`:core-crypto:test`) і JS-тестах (Vitest) без винятків і фільтрів.
