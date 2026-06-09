# Комплекс засобів аутентифікації (TOTP/OCRA)

Дипломна робота бакалавра з кібербезпеки: Android-аутентифікатор із
розширеними хеш-функціями та Web-стенд для демонстрації і перевірки
алгоритмів.

## Складові монорепозиторію

| Каталог | Призначення |
|---------|-------------|
| `android-app/` | Android-додаток: модуль `:core-crypto` (чисте криптоядро, Kotlin/JVM) та `:app` (Jetpack Compose, Material 3) |
| `web-stand/` | Статичний Web-стенд (Vite + Tailwind + @noble/hashes) для GitHub Pages |
| `shared/test-vectors/` | Спільні тестові вектори (генеруються незалежною Python-реалізацією) |
| `specs/` | Специфікація, план, контракти (Spec Kit) |

## Можливості

- TOTP за RFC 6238: SHA-1/256/512 + розширені BLAKE2s, BLAKE2b, BLAKE3,
  SHA3-256; довжина коду 6–10 цифр
- OCRA «виклик-відповідь» за RFC 6287 (профілі QN08, опціональна часова
  прив'язка)
- Захищене сховище: Android Keystore + EncryptedSharedPreferences, вхід
  лише через біометрію (BiometricPrompt)
- Безпечна міграція ключів між пристроями: AEAD-пакет через QR-кадри,
  квитанція імпорту, криптографічна деактивація (crypto-erase)

## Швидкий старт

Див. [specs/001-totp-ocra-auth/quickstart.md](specs/001-totp-ocra-auth/quickstart.md).

```bash
# Криптоядро (потрібен лише JDK 17+)
cd android-app && ./gradlew :core-crypto:test

# Android-додаток (потрібен Android SDK; модуль :app підключається
# автоматично за наявності ANDROID_HOME або local.properties)
./gradlew :app:assembleDebug

# Web-стенд
cd ../web-stand && npm ci && npm test && npm run dev

# Регенерація тестових векторів
cd ../shared/test-vectors && python3 -m venv .venv \
  && .venv/bin/pip install blake3 && .venv/bin/python generate.py
```

## Документація

- Конституція проєкту: `.specify/memory/constitution.md`
- Специфікація: `specs/001-totp-ocra-auth/spec.md`
- Контракти QR-форматів і криптоядра: `specs/001-totp-ocra-auth/contracts/`
