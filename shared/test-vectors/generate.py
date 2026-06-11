#!/usr/bin/env python3
"""Незалежний референс-генератор тестових векторів (FR-010, R7).

Третя незалежна реалізація (поряд із Bouncy Castle у Kotlin та @noble/hashes
у JS). Перед генерацією перевіряє сама себе на офіційних векторах
RFC 6238 (Додаток B) і RFC 6287 (Додаток C.1): будь-яка розбіжність
зупиняє генерацію.

Запуск:  python3 -m venv .venv && .venv/bin/pip install blake3
         .venv/bin/python generate.py
"""

import hashlib
import hmac as hmac_mod
import json
import sys
from pathlib import Path

try:
    from blake3 import blake3
except ImportError:
    sys.exit("Потрібен пакет blake3: .venv/bin/pip install blake3")

OUT_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# MAC-фабрика (contracts/crypto-core.md)
# ---------------------------------------------------------------------------

STANDARD = ("SHA1", "SHA256", "SHA512")
EXTENDED = ("SHA3-256", "BLAKE2S-256", "BLAKE2B-512", "BLAKE3-256")


def compute_mac(alg: str, key: bytes, data: bytes) -> bytes:
    if alg == "SHA1":
        return hmac_mod.new(key, data, hashlib.sha1).digest()
    if alg == "SHA256":
        return hmac_mod.new(key, data, hashlib.sha256).digest()
    if alg == "SHA512":
        return hmac_mod.new(key, data, hashlib.sha512).digest()
    if alg == "SHA3-256":
        return hmac_mod.new(key, data, hashlib.sha3_256).digest()
    if alg == "BLAKE2S-256":
        # Конвенція довгого ключа: аналогічно HMAC (FR-008)
        if len(key) > 32:
            key = hashlib.blake2s(key).digest()
        return hashlib.blake2s(data, key=key).digest()
    if alg == "BLAKE2B-512":
        if len(key) > 64:
            key = hashlib.blake2b(key).digest()
        return hashlib.blake2b(data, key=key).digest()
    if alg == "BLAKE3-256":
        if len(key) != 32:
            key = blake3(key).digest()
        return blake3(data, key=key).digest()
    raise ValueError(f"Невідомий алгоритм: {alg}")


# ---------------------------------------------------------------------------
# Динамічне усічення: RFC 4226 для стандартних, узагальнене для розширених
# ---------------------------------------------------------------------------

def truncate(alg: str, mac: bytes, digits: int) -> tuple[int, str]:
    """Повертає (offset, код)."""
    length = len(mac)
    if alg in STANDARD:
        if digits > 8:
            raise ValueError("Стандартні алгоритми обмежені 8 цифрами")
        offset = mac[-1] & 0x0F
        p = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    elif digits <= 8:
        offset = mac[-1] % (length - 4)
        p = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    else:
        offset = mac[-1] % (length - 8)
        p = int.from_bytes(mac[offset:offset + 8], "big") & 0x7FFFFFFFFFFFFFFF
    return offset, str(p % 10 ** digits).rjust(digits, "0")


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) та OCRA (RFC 6287, профілі QN08 [+T])
# ---------------------------------------------------------------------------

def totp(alg: str, secret: bytes, time_s: int, period: int, digits: int) -> str:
    counter = (time_s // period).to_bytes(8, "big")
    return truncate(alg, compute_mac(alg, secret, counter), digits)[1]


def ocra(suite: str, key: bytes, q: str, time_s: int | None = None) -> str:
    crypto = suite.split(":")[1]            # HOTP-SHA1-6
    _, halg, digits = crypto.split("-")
    data = suite.encode() + b"\x00"

    # Q: число -> hex-рядок (доповнений до парної довжини) -> 128 байтів
    qhex = format(int(q), "x")
    if len(qhex) % 2:
        qhex += "0"
    data += bytes.fromhex(qhex).ljust(128, b"\x00")

    datainput_suffix = suite.split(":")[2]  # QN08[-T30S|-T1M]
    if "-T" in datainput_suffix:
        step = {"T30S": 30, "T1M": 60}[datainput_suffix.split("-")[1]]
        if time_s is None:
            raise ValueError("Часовий профіль потребує time_s")
        data += (time_s // step).to_bytes(8, "big")

    return truncate(halg, compute_mac(halg, key, data), int(digits))[1]


# ---------------------------------------------------------------------------
# Самоперевірка на офіційних векторах RFC
# ---------------------------------------------------------------------------

RFC6238_SECRETS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890" * 6 + b"1234",
}
RFC6238_TIMES = (59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000)
RFC6238_EXPECTED = {
    "SHA1": ("94287082", "07081804", "14050471", "89005924", "69279037", "65353130"),
    "SHA256": ("46119246", "68084774", "67062674", "91819424", "90698825", "77737706"),
    "SHA512": ("90693936", "25091201", "99943326", "93441116", "38618901", "47863826"),
}

OCRA_KEY20 = b"12345678901234567890"
OCRA_KEY32 = b"12345678901234567890123456789012"
OCRA_KEY64 = b"1234567890" * 6 + b"1234"
RFC6287_QN08_SHA1 = (
    "237653", "243178", "653583", "740991", "608993",
    "388898", "816933", "224598", "750600", "294470",
)


def self_check() -> None:
    for alg, expected_codes in RFC6238_EXPECTED.items():
        for t, expected in zip(RFC6238_TIMES, expected_codes):
            got = totp(alg, RFC6238_SECRETS[alg], t, 30, 8)
            assert got == expected, f"RFC 6238 {alg} t={t}: {got} != {expected}"

    for i, expected in enumerate(RFC6287_QN08_SHA1):
        q = str(i) * 8
        got = ocra("OCRA-1:HOTP-SHA1-6:QN08", OCRA_KEY20, q)
        assert got == expected, f"RFC 6287 QN08 q={q}: {got} != {expected}"

    print("Самоперевірка RFC 6238 + RFC 6287 пройдена")


# ---------------------------------------------------------------------------
# Генерація векторів
# ---------------------------------------------------------------------------

def gen_totp() -> dict:
    cases = []
    # Офіційні вектори RFC 6238 (стандартні алгоритми, 8 цифр)
    for alg, expected_codes in RFC6238_EXPECTED.items():
        for t, expected in zip(RFC6238_TIMES, expected_codes):
            cases.append({
                "alg": alg, "secretHex": RFC6238_SECRETS[alg].hex(),
                "time": t, "period": 30, "digits": 8, "expected": expected,
                "source": "RFC 6238 Appendix B",
            })
    # Стандартні алгоритми: 6 цифр і нестандартний період
    for alg in STANDARD:
        for t, period, digits in ((59, 30, 6), (1111111111, 60, 7), (2000000000, 15, 6)):
            cases.append({
                "alg": alg, "secretHex": RFC6238_SECRETS[alg].hex(),
                "time": t, "period": period, "digits": digits,
                "expected": totp(alg, RFC6238_SECRETS[alg], t, period, digits),
            })
    # Розширені алгоритми: всі довжини, включно з 9-10 цифрами
    ext_secrets = {
        "коротк.": b"12345678901234567890",            # 20 Б
        "точний32": OCRA_KEY32,                          # 32 Б (= ключ BLAKE3)
        "довгий80": b"1234567890" * 8,                   # 80 Б (конвенція довгого ключа)
    }
    for alg in EXTENDED:
        for name, secret in ext_secrets.items():
            for t, digits in ((59, 6), (1111111111, 8), (1234567890, 9), (20000000000, 10)):
                cases.append({
                    "alg": alg, "secretHex": secret.hex(),
                    "time": t, "period": 30, "digits": digits,
                    "expected": totp(alg, secret, t, 30, digits),
                    "note": name,
                })
    return {"cases": cases}


def gen_truncation() -> dict:
    """Вектори усічення: MAC задано явно, перевіряються offset і код."""
    cases = []
    # Детерміновані «MAC» різних довжин
    macs = {
        20: hashlib.sha1(b"authapp-truncation-20").digest(),
        32: hashlib.sha256(b"authapp-truncation-32").digest(),
        64: hashlib.sha512(b"authapp-truncation-64").digest(),
    }
    for rule, algs in (("rfc4226", ["SHA1", "SHA256", "SHA512"]),
                       ("generalized", ["BLAKE2S-256", "BLAKE2B-512"])):
        for alg in algs:
            length = 20 if alg == "SHA1" else (32 if "256" in alg or alg == "SHA256" else 64)
            mac = macs[length]
            digit_set = (6, 8) if rule == "rfc4226" else (6, 8, 9, 10)
            for digits in digit_set:
                offset, code = truncate(alg, mac, digits)
                cases.append({
                    "rule": rule, "alg": alg, "macHex": mac.hex(),
                    "digits": digits, "expectedOffset": offset, "expected": code,
                })
    # Інваріант: для L=20 узагальнене правило тотожне RFC 4226
    mac20 = macs[20]
    inv_std = truncate("SHA1", mac20, 8)
    inv_gen = (mac20[-1] % 16, None)
    assert inv_std[0] == inv_gen[0], "Інваріант L=20 порушено"
    return {"cases": cases, "invariantNote":
            "для L=20 і digits<=8 узагальнене правило збігається з RFC 4226"}


def gen_ocra() -> dict:
    cases = []
    # Офіційні вектори RFC 6287 C.1 (один-бік, QN08, SHA1-6)
    for i, expected in enumerate(RFC6287_QN08_SHA1):
        cases.append({
            "suite": "OCRA-1:HOTP-SHA1-6:QN08", "keyHex": OCRA_KEY20.hex(),
            "q": str(i) * 8, "expected": expected, "source": "RFC 6287 Appendix C.1",
        })
    # Власні вектори: SHA256/SHA512 QN08 (генеруються референсом)
    for suite, key in (("OCRA-1:HOTP-SHA256-8:QN08", OCRA_KEY32),
                       ("OCRA-1:HOTP-SHA512-8:QN08", OCRA_KEY64)):
        for q in ("00000000", "11111111", "48217390", "99999999"):
            cases.append({"suite": suite, "keyHex": key.hex(), "q": q,
                          "expected": ocra(suite, key, q)})
    # Часові профілі
    for suite, key in (("OCRA-1:HOTP-SHA256-8:QN08-T30S", OCRA_KEY32),
                       ("OCRA-1:HOTP-SHA512-8:QN08-T1M", OCRA_KEY64)):
        for q, t in (("11111111", 1111111111), ("48217390", 1234567890)):
            cases.append({"suite": suite, "keyHex": key.hex(), "q": q, "time": t,
                          "expected": ocra(suite, key, q, t)})
    return {"cases": cases}


# ---------------------------------------------------------------------------
# Google Authenticator (otpauth-migration): ручне кодування protobuf —
# незалежний еталон для Kotlin-декодера (без залежності від protobuf-бібліотек)
# ---------------------------------------------------------------------------

def _varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | 0x80] if n else [b])
        if not n:
            return out


def _field_bytes(no: int, payload: bytes) -> bytes:
    return _varint((no << 3) | 2) + _varint(len(payload)) + payload


def _field_varint(no: int, value: int) -> bytes:
    return _varint((no << 3) | 0) + _varint(value)


def _otp_param(secret: bytes, name: str, issuer: str, alg: int, digits: int, otp_type: int) -> bytes:
    msg = (_field_bytes(1, secret) + _field_bytes(2, name.encode())
           + _field_bytes(3, issuer.encode()) + _field_varint(4, alg)
           + _field_varint(5, digits) + _field_varint(6, otp_type))
    return _field_bytes(1, msg)


def gen_gauth() -> dict:
    import base64
    import urllib.parse
    # Два валідні TOTP-токени + один HOTP (має бути пропущений імпортером)
    payload = (
        _otp_param(b"12345678901234567890", "Стенд:demo@stand", "Стенд", alg=1, digits=1, otp_type=2)
        + _otp_param(OCRA_KEY32, "acct2", "Test", alg=2, digits=2, otp_type=2)
        + _otp_param(b"12345678901234567890", "hotp-acct", "Skip", alg=1, digits=1, otp_type=1)
        + _field_varint(2, 1)   # version
        + _field_varint(3, 1)   # batch_size
        + _field_varint(4, 0)   # batch_index
    )
    b64 = base64.b64encode(payload).decode()
    uri = "otpauth-migration://offline?data=" + urllib.parse.quote(b64, safe="")
    return {
        "cases": [{
            "uri": uri,
            "skipped": 1,
            "expected": [
                {"issuer": "Стенд", "account": "demo@stand",
                 "secretHex": b"12345678901234567890".hex(), "alg": "SHA1", "digits": 6},
                {"issuer": "Test", "account": "acct2",
                 "secretHex": OCRA_KEY32.hex(), "alg": "SHA256", "digits": 8},
            ],
        }],
    }


def main() -> None:
    self_check()
    for name, data in (("totp", gen_totp()), ("truncation", gen_truncation()),
                       ("ocra", gen_ocra()), ("gauth", gen_gauth())):
        path = OUT_DIR / f"{name}.json"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n")
        print(f"{path.name}: {len(data['cases'])} кейсів")


if __name__ == "__main__":
    main()
