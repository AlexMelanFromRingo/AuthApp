# Tasks: Комплекс засобів аутентифікації (TOTP/OCRA)

**Input**: Design documents from `/specs/001-totp-ocra-auth/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: включені — Конституція (Принцип II) і FR-010 вимагають проходження
тестових векторів для кожного алгоритму; вектори пишуться ДО реалізації ядра.

**Organization**: задачі згруповані за user stories для незалежної реалізації
та перевірки кожної історії.

## Відповідність фаз замовника

| Фаза замовника | Фази tasks.md |
|----------------|---------------|
| Фаза 1: ініціалізація монорепо, каркаси, BiometricPrompt | Phase 1 (Setup) + Phase 2 (Foundational) |
| Фаза 2: криптоядро Kotlin, TOTP + Blake2/3/SHA-3 | Phase 2 (Foundational, T007–T012) |
| Фаза 3: OCRA в ядрі + екрани | Phase 5 (US3) |
| Фаза 4: UI/UX — сканер, список кодів, міграція | Phase 3 (US1) + Phase 6 (US4) |
| Фаза 5: Web-стенд | Phase 4 (US2) + частини Phase 5 (OCRA-симулятор) |

Порядок US-фаз відповідає пріоритетам специфікації (P1–P4) та ітераціям
plan.md (R9): стенд (US2) йде одразу після MVP, бо він — інструмент
демонстрації TOTP-циклу; OCRA-екрани (US3) потребують готового сканера з US1.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можна виконувати паралельно (різні файли, без залежностей)
- **[Story]**: до якої user story належить задача (US1–US4)

## Path Conventions

Монорепозиторій за plan.md: `android-app/` (Gradle-модулі `:core-crypto`,
`:app`), `web-stand/` (Vite), `shared/test-vectors/` (спільні вектори).

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: каркас монорепозиторію, збірка обох частин

- [x] T001 Створити структуру монорепозиторію: каталоги `android-app/`, `web-stand/`, `shared/test-vectors/`, кореневий `README.md` українською (огляд, посилання на specs/)
- [x] T002 Ініціалізувати Gradle: `android-app/settings.gradle.kts` (модулі `:core-crypto`, `:app`), `android-app/gradle/libs.versions.toml` (Kotlin 2.x, AGP, Compose BOM/Material3, androidx.biometric, security-crypto, CameraX, ML Kit barcode-scanning, Bouncy Castle bcprov-jdk18on, kotlinx.serialization, JUnit)
- [x] T003 [P] Створити модуль ядра: `android-app/core-crypto/build.gradle.kts` — чистий Kotlin/JVM (kotlin("jvm")), залежності BC + kotlinx-serialization-json + тести; без Android SDK
- [x] T004 [P] Створити каркас додатка: `android-app/app/build.gradle.kts` (minSdk 26, targetSdk 35, Compose), `AndroidManifest.xml` (`android:allowBackup="false"`, дозвіл CAMERA), `app/src/main/kotlin/ua/authapp/MainActivity.kt` + тема Material 3 у `ui/theme/` (динамічні кольори API 31+ з фолбеком), `res/values/strings.xml` українською
- [x] T005 [P] Ініціалізувати Web-стенд: `web-stand/package.json` (vite, tailwindcss, @noble/hashes, qrcode, vitest), `web-stand/vite.config.js`, `web-stand/index.html` — каркас трьох сторінок українською, Tailwind підключено
- [x] T006 [P] Налаштувати CI: `.github/workflows/ci.yml` (Gradle-тести core-crypto + Vitest web-stand на push) та `.github/workflows/pages.yml` (збірка `web-stand/dist` → GitHub Pages)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: криптоядро на векторах + біометричний бар'єр + сховище — без цього жодна історія не працює

**⚠️ CRITICAL**: користувацькі історії не починати до завершення цієї фази

- [x] T007 Написати референс-генератор векторів `shared/test-vectors/generate.py` (Python: hashlib + blake3): TOTP для 7 алгоритмів × digits 6/8/9/10, вектори узагальненого усічення (MAC→offset→код), OCRA-вектори RFC 6287 Appendix C; згенерувати і закомітити `totp.json`, `truncation.json`, `ocra.json` (формат — contracts/crypto-core.md)
- [x] T008 [P] Реалізувати словник алгоритмів і MAC-фабрику в `android-app/core-crypto/src/main/kotlin/ua/authapp/crypto/mac/MacFactory.kt`: HMAC-SHA1/256/512 через javax.crypto, HMAC-SHA3-256 + keyed Blake2s/Blake2b/Blake3 через BC, конвенція довгого ключа (FR-008)
- [x] T009 [P] Реалізувати усічення в `android-app/core-crypto/src/main/kotlin/ua/authapp/crypto/truncation/DynamicTruncation.kt`: RFC 4226 (нібл) для стандартних, узагальнене `mod (L−4)` / 8 байтів для digits 9–10 для розширених (contracts/crypto-core.md), включно з інваріантом тотожності при L=20
- [x] T010 Реалізувати TOTP у `android-app/core-crypto/src/main/kotlin/ua/authapp/crypto/totp/Totp.kt`: T0=0, period 15–120, digits 6–10, провідні нулі (залежить від T008, T009)
- [x] T011 [P] Реалізувати кодеки в `android-app/core-crypto/src/main/kotlin/ua/authapp/crypto/codec/`: `Base32.kt` (RFC 4648 без паддінгу) і `OtpUri.kt` — парсинг/серіалізація `otpauth://totp`, `authapp://totp`, `authapp://ocra-token` з валідацією і україномовними помилками (contracts/qr-uri-schemes.md §1–2, FR-006)
- [x] T012 Написати векторні тести ядра `android-app/core-crypto/src/test/kotlin/ua/authapp/crypto/VectorTest.kt`: читання `shared/test-vectors/{totp,truncation}.json`, 100% кейсів зелені, 0 skipped (SC-001)
- [x] T013 [P] Реалізувати біометричний бар'єр: `android-app/app/src/main/kotlin/ua/authapp/biometric/BiometricGate.kt` (BiometricPrompt, BIOMETRIC_STRONG, повторний запит при поверненні з фону) + екран `ui/UnlockScreen.kt`; обробка «біометрія недоступна/не налаштована» з поясненням (FR-002, edge case)
- [x] T014 [P] Реалізувати сховище: `android-app/app/src/main/kotlin/ua/authapp/storage/Token.kt` (модель за data-model.md) і `storage/TokenStore.kt` — EncryptedSharedPreferences з майстер-ключем Keystore AES-256-GCM (без setUserAuthenticationRequired, R4), CRUD + виявлення дублікатів; JVM-тести парсингу/серіалізації в `app/src/test/`
- [x] T015 Зібрати навігаційний каркас `android-app/app/src/main/kotlin/ua/authapp/ui/AppNav.kt`: Unlock → TokenList (заглушка), `FLAG_SECURE` на вікні активності (FR-003)

**Checkpoint**: `./gradlew :core-crypto:test` зелений на всіх векторах; додаток запускається лише через біометрію

---

## Phase 3: User Story 1 — Додавання токена та генерація TOTP-коду (Priority: P1) 🎯 MVP

**Goal**: користувач сканує QR, токен у захищеному сховищі, на головному екрані живий код з копіюванням по тапу

**Independent Test**: відсканувати QR із секретом тестового вектора RFC 6238 і звірити код з еталоном; сценарії приймання US1 зі spec.md

### Implementation for User Story 1

- [x] T016 [US1] Реалізувати сканер `android-app/app/src/main/kotlin/ua/authapp/scanner/QrScanner.kt`: CameraX Preview + ML Kit barcode analyzer як composable; обробка відмови в дозволі камери з поясненням (edge case)
- [x] T017 [US1] Реалізувати екран додавання `android-app/app/src/main/kotlin/ua/authapp/ui/AddTokenScreen.kt`: сканування → парсинг OtpUri (T011) → україномовні помилки для непідтримуваних QR → діалог дубліката «замінити чи додати окремо» → збереження в TokenStore
- [x] T018 [US1] Реалізувати головний екран `android-app/app/src/main/kotlin/ua/authapp/ui/TokenListScreen.kt`: список токенів (M3 Cards), оновлення кодів щосекунди, круговий індикатор залишку періоду, тап → буфер обміну + сповіщення «Код скопійовано» (FR-010/011), перейменування і видалення з підтвердженням (FR-004)
- [x] T019 [US1] Реалізувати `android-app/app/src/main/kotlin/ua/authapp/ui/TokenListViewModel.kt`: генерація кодів через :core-crypto поза головним потоком, тік без пропусків (<50 мс на код), жодних секретів/кодів у логах (FR-003)
- [ ] T020 [US1] Прогнати сценарії приймання US1 (spec.md): біометрія при першому запуску, токен SHA-1 6 цифр із вектора, BLAKE3 9 цифр, копіювання по тапу, збереження після перезавантаження — зафіксувати результати в `specs/001-totp-ocra-auth/checklists/us1-validation.md`

**Checkpoint**: MVP готовий — додаток самодостатній як аутентифікатор

---

## Phase 4: User Story 2 — Перевірка алгоритмів на Web-стенді (Priority: P2)

**Goal**: статичний стенд генерує QR із будь-якими параметрами TOTP і валідує коди з додатка — інструмент демонстрації на захисті

**Independent Test**: стенд сам обчислює еталонний код для заданих параметрів; Vitest на спільних векторах; цикл «стенд → QR → додаток → код → збіг»

### Implementation for User Story 2

- [x] T021 [P] [US2] Реалізувати дзеркало ядра `web-stand/src/crypto/mac.js`, `truncation.js`, `totp.js` на @noble/hashes — побітова відповідність contracts/crypto-core.md (обидва правила усічення, keyed/HMAC конструкції)
- [x] T022 [P] [US2] Написати тести `web-stand/tests/crypto.test.js` (Vitest): читання `../shared/test-vectors/{totp,truncation}.json`, 100% кейсів зелені (SC-001)
- [x] T023 [US2] Реалізувати генерацію QR: `web-stand/src/qr.js` (обгортка пакета qrcode) + сторінка `web-stand/src/pages/totp.js` — форма параметрів (7 алгоритмів, digits 6–10, period, секрет: ввести/згенерувати CSPRNG), вибір схеми otpauth:///authapp:// за алгоритмом (contracts §1)
- [x] T024 [US2] Реалізувати валідатор кодів на сторінці TOTP: введення коду з додатка, вікно ±1 період, чіткий результат «збігається/не збігається» + поточний еталонний код для самоперевірки (FR-022); вся локалізація українською (FR-024)
- [ ] T025 [US2] Розгорнути на GitHub Pages (workflow з T006), перевірити сценарії 2 і 6 quickstart.md у Chrome та Firefox (SC-004, SC-008), зафіксувати в `specs/001-totp-ocra-auth/checklists/us2-validation.md`

**Checkpoint**: повний демо-цикл TOTP для всіх 7 алгоритмів працює

---

## Phase 5: User Story 3 — OCRA: виклик-відповідь (Priority: P3)

**Goal**: стенд видає QR-виклик, додаток на окремому екрані обчислює відгук за RFC 6287, стенд валідує

**Independent Test**: вектори RFC 6287 Appendix C у ядрі та стенді; цикл «виклик → сканування → відгук → валідація»

### Implementation for User Story 3

- [x] T026 [P] [US3] Реалізувати парсер профілів `android-app/core-crypto/src/main/kotlin/ua/authapp/crypto/ocra/OcraSuite.kt`: лише QN08, хеші SHA1/256/512, digits 6/8, опціональний T30S/T1M; відхилення C/P/S (FR-013, data-model.md)
- [x] T027 [US3] Реалізувати обчислення відгуку `android-app/core-crypto/src/main/kotlin/ua/authapp/crypto/ocra/Ocra.kt`: DataInput = suite ‖ 0x00 ‖ Q(128 Б за RFC §5.1) [‖ T 8 Б BE], MAC + усічення з T008/T009 (FR-015, contracts §3)
- [x] T028 [US3] Додати OCRA-вектори в `android-app/core-crypto/src/test/kotlin/ua/authapp/crypto/OcraVectorTest.kt` на `shared/test-vectors/ocra.json` — 100% зелені (SC-002)
- [x] T029 [US3] Реалізувати екран `android-app/app/src/main/kotlin/ua/authapp/ui/OcraScreen.kt`: сканування QR-виклику (повторне використання T016), парсинг `authapp://ocra-challenge` у `core-crypto/codec/OtpUri.kt`, вибір токена при неоднозначності за label (FR-012), показ відгуку великим шрифтом + копіювання по тапу
- [x] T030 [P] [US3] Реалізувати `web-stand/src/crypto/ocra.js` + тести в `web-stand/tests/ocra.test.js` на тих самих векторах
- [x] T031 [US3] Реалізувати сторінку-симулятор `web-stand/src/pages/ocra.js`: конфігурація suite+секрет, провіжининг-QR `authapp://ocra-token`, генерація виклику (CSPRNG QN08, cid, exp=120 с) у QR, валідація відгуку (вікно ±1 крок для T-профілів), стани ISSUED→VALIDATED/EXPIRED у пам'яті сесії, відхилення повторної валідації (FR-014, FR-023)
- [ ] T032 [US3] Прогнати сценарії приймання US3 (spec.md) + сценарій 3 quickstart.md, зафіксувати в `specs/001-totp-ocra-auth/checklists/us3-validation.md`

**Checkpoint**: повний цикл OCRA працює; вектори RFC 6287 зелені в обох реалізаціях

---

## Phase 6: User Story 4 — Міграція ключів на інший пристрій (Priority: P4)

**Goal**: експорт зашифрованого пакета QR-кадрами/файлом, імпорт із квитанцією, деактивація crypto-erase на старому пристрої

**Independent Test**: на одному пристрої/емуляторі — експорт → видалення → імпорт → ідентичні коди; неправильна фраза → відмова

### Implementation for User Story 4

- [x] T033 [P] [US4] Реалізувати криптографію міграції `android-app/core-crypto/src/main/kotlin/ua/authapp/crypto/migration/MigrationCrypto.kt`: Argon2id (BC, m=64MiB/t=3/p=4) → HKDF-SHA256 → K_enc/K_rcpt, AES-256-GCM seal/open маніфесту, квитанція HMAC-SHA256 + порівняння константним часом; тести round-trip + неправильна фраза + підроблений MAC у `core-crypto/src/test/.../MigrationCryptoTest.kt` (R5, data-model.md)
- [x] T034 [US4] Реалізувати кадрування `android-app/core-crypto/src/main/kotlin/ua/authapp/crypto/migration/FrameCodec.kt`: заголовок (pid, salt, kdfParams, nonce, n) + кадри ≤512 Б base64url, URI `authapp://migrate`/`migrate-receipt`, бітова карта дозбирання; тести розбирання в довільному порядку і втрати кадру (contracts §4–5, FR-017)
- [x] T035 [US4] Реалізувати екран експорту `android-app/app/src/main/kotlin/ua/authapp/ui/ExportScreen.kt`: вибір токенів, парольна фраза (подвійне введення), послідовний показ QR-кадрів з навігацією, альтернатива — share файлу `*.authapp-backup` (FR-016)
- [x] T036 [US4] Реалізувати екран імпорту `android-app/app/src/main/kotlin/ua/authapp/ui/ImportScreen.kt`: сканування кадрів із прогресом «кадр X із N», дозбирання пропущених, парольна фраза, атомарний імпорт (все або нічого), показ QR-квитанції після успіху (FR-017, FR-018)
- [x] T037 [US4] Реалізувати деактивацію в `android-app/app/src/main/kotlin/ua/authapp/ui/DeactivateFlow.kt` + `storage/TokenStore.kt#cryptoErase`: сканування і верифікація квитанції → штатна деактивація (видалення майстер-ключа з Keystore + затирання prefs); примусова — лише через подвійне підтвердження; попередження про незворотність перед будь-якою (FR-019)
- [ ] T038 [US4] Прогнати сценарій 4 quickstart.md на двох інсталяціях (SC-006), зафіксувати в `specs/001-totp-ocra-auth/checklists/us4-validation.md`

**Checkpoint**: усі чотири історії незалежно працюють

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T039 [P] Аудит безпеки (SC-007): FLAG_SECURE на всіх екранах із секретами, `adb logcat` без секретів/кодів у всіх сценаріях, `adb backup` порожній, зануляння ключів міграції в пам'яті після операції
- [ ] T040 [P] Локалізаційна вичитка (FR-024): усі strings.xml, тексти стенду, логи і коментарі обох кодових баз — виключно українською
- [ ] T041 [P] Створити довідкову сторінку `web-stand/src/pages/about.js`: опис 7 алгоритмів, узагальненого усічення і протоколу OCRA з посиланнями на RFC — матеріал для захисту диплома
- [ ] T042 Оновити кореневий `README.md`: інструкції збірки обох частин, посилання на quickstart.md і живий стенд на Pages
- [ ] T043 Виконати повну валідацію quickstart.md (сценарії 1–6, SC-001…SC-008) і зафіксувати підсумок у `specs/001-totp-ocra-auth/checklists/final-validation.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: без залежностей
- **Phase 2 (Foundational)**: після Phase 1; БЛОКУЄ всі історії. Внутрішні: T007 → T012 (вектори до тестів); T008, T009 → T010; T012 після T008–T011
- **Phase 3 (US1)**: після Phase 2 (сканер T016 потребує каркаса T004; екрани — сховища T014, бар'єра T013, навігації T015)
- **Phase 4 (US2)**: після T007 (вектори) і T005 (каркас стенду); НЕ залежить від US1, але демо-цикл T025 потребує встановленого додатка з US1
- **Phase 5 (US3)**: ядро (T026–T028, T030) — після Phase 2; екран T029 — після T016 (сканер); сторінка T031 — після T021 (crypto стенду)
- **Phase 6 (US4)**: T033/T034 — після Phase 2; екрани T035–T037 — після T014, T016
- **Phase 7 (Polish)**: після завершення бажаних історій

### User Story Dependencies

- **US1 (P1)**: лише Foundational — самодостатній MVP
- **US2 (P2)**: незалежна від US1 (стенд самоперевіряється еталонним кодом); повний демо-цикл — з US1
- **US3 (P3)**: ядро незалежне; екран повторно використовує сканер US1 (T016)
- **US4 (P4)**: повторно використовує сканер US1 і сховище Phase 2

### Parallel Opportunities

- Phase 1: T003, T004, T005, T006 — паралельно після T002
- Phase 2: T007, T008, T009, T011, T013, T014 — паралельно (різні файли)
- Після Phase 2: US2-ядро (T021–T022) і US3-ядро (T026–T028) можуть іти паралельно з US1-екранами
- Усередині US3: T026, T030 паралельно; усередині US4: T033 паралельно з T035-заготовкою

## Parallel Example: Phase 2

```bash
# Після T007 (вектори) запускати одночасно:
Task: "MAC-фабрика в core-crypto/src/main/kotlin/ua/authapp/crypto/mac/MacFactory.kt"
Task: "Усічення в core-crypto/src/main/kotlin/ua/authapp/crypto/truncation/DynamicTruncation.kt"
Task: "Кодеки в core-crypto/src/main/kotlin/ua/authapp/crypto/codec/"
Task: "Біометричний бар'єр в app/src/main/kotlin/ua/authapp/biometric/"
Task: "Сховище в app/src/main/kotlin/ua/authapp/storage/"
```

## Implementation Strategy

### MVP First (US1)

1. Phase 1 → Phase 2 (вектори зелені — головний гейт якості)
2. Phase 3 (US1) → **СТОП і валідація T020** → робочий аутентифікатор
3. Далі за пріоритетами: US2 (демо-інструмент) → US3 (наукова новизна OCRA) → US4 (міграція)

### Incremental Delivery

Кожна фаза завершується checkpoint-валідацією і комітом; стенд деплоїться
на Pages уже після US2 і нарощується сторінкою OCRA в US3. До захисту
диплома мінімально достатньо: Phases 1–5 (MVP + стенд + OCRA); US4 —
повна комплектація.

## Notes

- Комітити після кожної задачі або логічної групи (домовленість із замовником)
- Векторні тести (T012, T022, T028) — обов'язковий гейт перед злиттям змін ядра (Конституція, Принцип II)
- Уникати: секретів у логах, English-текстів у UI, змін стандартного усічення для SHA-1/256/512
