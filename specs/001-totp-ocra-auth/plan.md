# Implementation Plan: Комплекс засобів аутентифікації (TOTP/OCRA)

**Branch**: `001-totp-ocra-auth` | **Date**: 2026-06-09 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-totp-ocra-auth/spec.md`

## Summary

Android-аутентифікатор (Kotlin, Jetpack Compose, Material 3) із захищеним
сховищем (Keystore + EncryptedSharedPreferences, доступ через
BiometricPrompt), генерацією TOTP за RFC 6238 зі стандартними
(SHA-1/256/512) та розширеними (BLAKE2s/b, BLAKE3, SHA3) алгоритмами,
OCRA «виклик-відповідь» за RFC 6287 і безпечною міграцією ключів
(AEAD-пакет через QR-кадри + квитанція + crypto-erase). Плюс статичний
Web-стенд (Vite + vanilla JS + Tailwind, @noble/hashes) на GitHub Pages для
генерації QR і незалежної валідації всіх алгоритмів. Технічний підхід:
чистий Kotlin/JVM модуль `core-crypto` розробляється першим за спільними
тестовими векторами (Python-референс), JS-реалізація стенду доказово
еквівалентна через ті самі вектори.

## Technical Context

**Language/Version**: Kotlin 2.x (JDK 17) для Android; JavaScript ES2022
(Node 20 для збірки/тестів) для стенду; Python 3.11 — лише генератор
тестових векторів

**Primary Dependencies**: Android: Compose BOM + Material 3, CameraX,
ML Kit barcode-scanning, androidx.biometric, androidx.security-crypto,
Bouncy Castle (bcprov-jdk18on), kotlinx.serialization. Web: Vite,
TailwindCSS, @noble/hashes, qrcode, Vitest. Деталі та обґрунтування —
[research.md](research.md) R1–R8

**Storage**: EncryptedSharedPreferences (майстер-ключ AES-256-GCM в Android
Keystore); Web-стенд — лише пам'ять сесії браузера, без персистенції

**Testing**: JUnit/kotlin.test для `:core-crypto` (JVM, без емулятора);
Vitest для стенду; обидва читають спільні JSON-вектори з
`shared/test-vectors/`; біометрія/камера — задокументовані ручні сценарії
([quickstart.md](quickstart.md))

**Target Platform**: Android 8.0+ (minSdk 26, targetSdk 35); браузери —
дві останні мажорні версії Chrome/Firefox; хостинг стенду — GitHub Pages

**Project Type**: mobile-app + static-web у монорепозиторії

**Performance Goals**: генерація коду < 50 мс (UI-тік 1 с без пропусків);
реакція стенду на введення < 100 мс; Argon2id при міграції ≤ 3 с на
середньому пристрої

**Constraints**: повністю офлайн (жодного бекенду і телеметрії);
FLAG_SECURE на екранах із секретами; `android:allowBackup="false"`;
усі тексти/логи/коментарі — українською (Конституція, Принцип IV)

**Scale/Scope**: ≤ 100 токенів; 5 екранів додатка (розблокування, список,
додавання/сканер, OCRA, міграція + налаштування в рамках списку);
3 сторінки стенду (TOTP-генератор/валідатор, OCRA-симулятор, довідка)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Принцип | Вимога | Відповідність плану |
|---------|--------|---------------------|
| I. Безпека понад усе | Keystore + шифроване сховище; СУВОРО BiometricPrompt; без секретів у логах/бекапах/скріншотах | ✅ R4: EncryptedSharedPreferences + Keystore-майстер-ключ; BiometricPrompt (BIOMETRIC_STRONG) на запуск/повернення; FLAG_SECURE, allowBackup=false (quickstart SC-007) |
| II. Криптографічне ядро | RFC 6238 + BLAKE2s/b, BLAKE3, SHA3; тестові вектори; заборона самописних хешів | ✅ R1/R2: Bouncy Castle і @noble/hashes (перевірені бібліотеки); R7: незалежний Python-референс векторів; contracts/crypto-core.md |
| III. Монорепозиторій | `android-app/` + `web-stand/`; спільні артефакти узгоджено | ✅ Структура нижче; вектори у `shared/test-vectors/` на верхньому рівні |
| IV. UI/UX та локалізація | Jetpack Compose + Material 3; все українською | ✅ Compose/M3 (R8, динамічні кольори з фолбеком); українська — наскрізна вимога FR-024 |

**Початкова оцінка**: PASS, порушень немає.
**Повторна оцінка після Phase 1**: PASS — артефакти дизайну не вводять
відхилень (Complexity Tracking порожній).

## Project Structure

### Documentation (this feature)

```text
specs/001-totp-ocra-auth/
├── plan.md              # Цей файл
├── research.md          # Phase 0: рішення R1–R9
├── data-model.md        # Phase 1: сутності та валідація
├── quickstart.md        # Phase 1: збірка і валідаційні сценарії
├── contracts/
│   ├── qr-uri-schemes.md    # otpauth:// та authapp:// формати
│   └── crypto-core.md       # MAC-фабрика, усічення, формат векторів
└── tasks.md             # Phase 2 (/speckit-tasks — НЕ створюється цією командою)
```

### Source Code (repository root)

```text
android-app/
├── settings.gradle.kts, gradle/libs.versions.toml
├── core-crypto/                  # чистий Kotlin/JVM, без Android SDK
│   └── src/
│       ├── main/kotlin/ua/authapp/crypto/
│       │   ├── mac/              # MAC-фабрика (HMAC + keyed BLAKE2/3)
│       │   ├── truncation/       # RFC 4226 + узагальнене усічення
│       │   ├── totp/             # RFC 6238
│       │   ├── ocra/             # RFC 6287 (QN08, опц. T)
│       │   ├── codec/            # Base32, URI-парсери authapp://
│       │   └── migration/        # Argon2id+HKDF, AEAD-пакет, квитанція
│       └── test/kotlin/          # тести на shared/test-vectors/*.json
└── app/                          # Android-застосунок
    └── src/
        ├── main/kotlin/ua/authapp/
        │   ├── storage/          # EncryptedSharedPreferences + Keystore
        │   ├── biometric/        # бар'єр BiometricPrompt
        │   ├── scanner/          # CameraX + ML Kit
        │   ├── ui/               # Compose: Unlock, TokenList, AddToken,
        │   │                     #          Ocra, Migration (M3)
        │   └── migration/        # оркестрація експорт/імпорт/деактивація
        ├── test/                 # JVM-тести (сховище, парсери)
        └── androidTest/          # мінімальні інструментальні перевірки

web-stand/
├── index.html, vite.config.js, package.json, tailwind.config.js
├── src/
│   ├── crypto/                   # дзеркало core-crypto на @noble/hashes
│   │   ├── mac.js, truncation.js, totp.js, ocra.js
│   ├── qr.js                     # генерація QR (qrcode)
│   ├── pages/                    # totp.js, ocra.js, about.js (укр. UI)
│   └── styles/
└── tests/                        # Vitest на shared/test-vectors/*.json

shared/
└── test-vectors/
    ├── generate.py               # Python-референс (hashlib + blake3)
    ├── totp.json, truncation.json, ocra.json
```

**Structure Decision**: монорепозиторій із трьома коренями: `android-app/`
(Gradle-модулі `:core-crypto` і `:app`), `web-stand/` (Vite-статика) і
`shared/test-vectors/` (спільний артефакт за Принципом III). Ядро
`:core-crypto` ізольоване від Android SDK для швидких JVM-тестів і
розробляється першою ітерацією (R9).

## Iterations (порядок реалізації, вимога замовника)

1. **Криптоядро Kotlin**: `shared/test-vectors/` + `:core-crypto`
   (MAC-фабрика → усічення → TOTP → вектори зелені).
2. **Ядро стенду**: `web-stand/src/crypto/` на тих самих векторах (Vitest).
3. **Додаток-MVP (US1)**: сховище + біометрія + список токенів + сканер QR.
4. **Демо-цикл TOTP (US2)**: сторінка стенду генерація QR/валідація кодів.
5. **OCRA (US3)**: ядро OCRA вже готове з ітерації 1 → екран додатка +
   сторінка-симулятор стенду.
6. **Міграція (US4)**: експорт/кадри/імпорт/квитанція/crypto-erase.
7. **Гартування**: FLAG_SECURE-аудит, логи, едж-кейси, локалізаційна
   вичитка, деплой Pages.

## Complexity Tracking

> Порушень Constitution Check немає — таблиця не заповнюється.
