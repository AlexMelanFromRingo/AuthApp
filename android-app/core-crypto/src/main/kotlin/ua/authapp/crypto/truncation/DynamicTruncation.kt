package ua.authapp.crypto.truncation

import ua.authapp.crypto.mac.HashAlgorithm

/** Результат усічення: позиція вікна та готовий код із провідними нулями. */
data class TruncationResult(val offset: Int, val code: String)

/**
 * Динамічне усічення (contracts/crypto-core.md, FR-007/FR-009).
 *
 * Стандартні алгоритми (SHA-1/256/512) — строго RFC 4226:
 * offset = молодший нібл останнього байта, 4 байти, 31 значущий біт.
 * Так гарантується проходження офіційних векторів RFC 6238.
 *
 * Розширені алгоритми — узагальнене правило, що рівномірно покриває весь MAC:
 * offset = останній байт mod (L−4); для 9–10 цифр беруться 8 байтів
 * (63 значущі біти), бо 31 біт не покриває 10^10 значень.
 * Інваріант: для L=20 і digits<=8 узагальнене правило тотожне RFC 4226.
 */
object DynamicTruncation {

    fun truncate(algorithm: HashAlgorithm, mac: ByteArray, digits: Int): TruncationResult {
        require(digits in 6..10) { "Довжина коду має бути від 6 до 10 цифр, отримано $digits" }
        if (!algorithm.isExtended) {
            require(digits <= 8) { "Стандартні алгоритми обмежені 8 цифрами (RFC 4226)" }
            return rfc4226(mac, digits)
        }
        return generalized(mac, digits)
    }

    private fun rfc4226(mac: ByteArray, digits: Int): TruncationResult {
        val offset = mac.last().toInt() and 0x0F
        val p = readBits31(mac, offset)
        return TruncationResult(offset, format(p, digits))
    }

    private fun generalized(mac: ByteArray, digits: Int): TruncationResult {
        val length = mac.size
        val lastByte = mac.last().toInt() and 0xFF
        return if (digits <= 8) {
            val offset = lastByte % (length - 4)
            TruncationResult(offset, format(readBits31(mac, offset), digits))
        } else {
            val offset = lastByte % (length - 8)
            val p = readBits63(mac, offset)
            TruncationResult(offset, format(p, digits))
        }
    }

    private fun readBits31(mac: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 4) {
            value = (value shl 8) or (mac[offset + i].toLong() and 0xFF)
        }
        return value and 0x7FFFFFFFL
    }

    private fun readBits63(mac: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 8) {
            value = (value shl 8) or (mac[offset + i].toLong() and 0xFF)
        }
        return value and 0x7FFFFFFFFFFFFFFFL
    }

    private fun format(value: Long, digits: Int): String {
        var mod = 1L
        repeat(digits) { mod *= 10 }
        return (value % mod).toString().padStart(digits, '0')
    }
}
