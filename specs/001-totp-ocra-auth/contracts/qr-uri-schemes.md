# Контракт: URI-схеми QR-кодів

**Версія**: 1 | **Споживачі**: Android-додаток ↔ Web-стенд

Усі власні URI використовують схему `authapp://` з обов'язковим параметром
`v` (версія формату). Невідома версія або відсутній обов'язковий параметр →
відмова з поясненням (FR-006). Значення параметрів — URL-encoded; бінарні
дані — base64url без паддінгу.

## 1. Провіжининг TOTP-токена

**Стандартні алгоритми** — класичний otpauth (сумісність зі сторонніми
аутентифікаторами):

```
otpauth://totp/{issuer}:{account}?secret={BASE32}&issuer={issuer}
        &algorithm={SHA1|SHA256|SHA512}&digits={6..8}&period={15..120}
```

**Розширені алгоритми** — власна схема:

```
authapp://totp?v=1&secret={BASE32}&alg={SHA3-256|BLAKE2S-256|BLAKE2B-512|BLAKE3-256}
       &digits={6..10}&period={15..120}&issuer={...}&account={...}
```

Обов'язкові: `v`, `secret`, `alg`. Типово: `digits=6`, `period=30`.

## 2. Провіжининг OCRA-токена

```
authapp://ocra-token?v=1&secret={BASE32}&suite={OCRA-1:HOTP-SHA256-8:QN08}
       &issuer={...}&account={...}
```

Обов'язкові: `v`, `secret`, `suite`. Suite валідується за data-model.md
(лише QN08, опціональний T30S/T1M).

## 3. OCRA-виклик (стенд → додаток)

```
authapp://ocra-challenge?v=1&suite={...}&q={8 цифр}&cid={base64url 8Б}
       &exp=120&label={підказка токена}
```

Обов'язкові: `v`, `suite`, `q`, `cid`. `label` — необов'язкова підказка для
вибору токена; за неоднозначності додаток пропонує вибір (FR-012).
Обчислення відгуку (FR-015):

```
DataInput = suite ‖ 0x00 ‖ Q_encoded(128 Б) [‖ T(8 Б, big-endian)]
Q_encoded: десяткове число → hex-рядок → байти, вирівнювання вліво,
           доповнення нулями до 128 Б (RFC 6287 §5.1)
T = floor(unix_time / крок_T_із_suite)
response = усічення(MAC(K, DataInput), digits_із_suite)
```

Стенд: виклик живе 120 с у пам'яті сесії, одна успішна валідація,
для T-профілів вікно ±1 крок (FR-014, FR-015).

## 4. Кадри пакета міграції (старий → новий пристрій)

```
authapp://migrate?v=1&pid={base64url}&i={1..n}&n={кількість}&data={base64url ≤512Б}
```

- Кадр `i=1` (`data` = заголовок, JSON): `{version, salt, kdf:{m,t,p}, nonce, ctLen}`
- Кадри `i=2..n`: послідовні фрагменти шифротексту AES-256-GCM.
- Імпортер приймає кадри в довільному порядку, веде бітову карту,
  показує прогрес «кадр X із N відсутній», дозволяє дозбирання (FR-017).
- Той самий пакет може передаватися одним файлом `*.authapp-backup`
  (бінарна конкатенація заголовка і шифротексту).

## 5. Квитанція імпорту (новий → старий пристрій)

```
authapp://migrate-receipt?v=1&pid={base64url}&mac={base64url 32Б}
```

`mac = HMAC-SHA256(K_rcpt, manifestHash ‖ nonce)`. Старий пристрій звіряє
константним часом; збіг → розблоковується штатна деактивація (FR-018);
розбіжність/відсутність → лише примусова деактивація з подвійним
підтвердженням (FR-019).

## 6. Імпорт Google Authenticator (лише читання)

```
otpauth-migration://offline?data={URL-encoded base64(protobuf MigrationPayload)}
```

Схема MigrationPayload (FR-026): поле 1 — repeated OtpParameters
{1: secret(bytes), 2: name, 3: issuer, 4: algorithm(1=SHA1,2=SHA256,3=SHA512,
4=MD5), 5: digits(1=6,2=8), 6: type(1=HOTP,2=TOTP), 7: counter};
поля 2–5 — version/batch_size/batch_index/batch_id. Період — фіксовано 30 с.
Додаток лише читає цей формат; несумісні записи (HOTP, MD5, секрет поза
10..64 Б) пропускаються з підрахунком. Декодер — мінімальний власний
wire-format-парсер (varint + length-delimited), еталонний вектор —
`shared/test-vectors/gauth.json` (незалежне Python-кодування).

## Правила еволюції

Будь-яка несумісна зміна параметрів → інкремент `v`; додаток і стенд MUST
відхиляти більші версії з повідомленням про необхідність оновлення.
