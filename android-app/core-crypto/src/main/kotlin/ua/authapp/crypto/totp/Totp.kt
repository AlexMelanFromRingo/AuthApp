package ua.authapp.crypto.totp

import ua.authapp.crypto.mac.HashAlgorithm
import ua.authapp.crypto.mac.MacFactory
import ua.authapp.crypto.truncation.DynamicTruncation

/**
 * TOTP за RFC 6238: лічильник = floor((unixTime − T0) / period), T0 = 0.
 * Підтримує стандартні (6–8 цифр) та розширені (до 10 цифр) конфігурації.
 */
object Totp {

    fun generate(
        algorithm: HashAlgorithm,
        secret: ByteArray,
        unixTimeSeconds: Long,
        period: Int = 30,
        digits: Int = 6,
    ): String {
        require(period in 15..120) { "Період має бути від 15 до 120 секунд, отримано $period" }
        require(secret.isNotEmpty()) { "Секрет не може бути порожнім" }
        val counter = unixTimeSeconds / period
        val counterBytes = ByteArray(8)
        for (i in 0 until 8) {
            counterBytes[7 - i] = ((counter ushr (i * 8)) and 0xFF).toByte()
        }
        val mac = MacFactory.compute(algorithm, secret, counterBytes)
        return DynamicTruncation.truncate(algorithm, mac, digits).code
    }

    /**
     * Перевірка коду з вікном ±window періодів (стенд використовує window=1;
     * FR-022). Порівняння — константним часом.
     */
    fun verify(
        algorithm: HashAlgorithm,
        secret: ByteArray,
        code: String,
        unixTimeSeconds: Long,
        period: Int = 30,
        digits: Int = 6,
        window: Int = 1,
    ): Boolean {
        for (step in -window..window) {
            val candidate = generate(algorithm, secret, unixTimeSeconds + step.toLong() * period, period, digits)
            if (constantTimeEquals(candidate, code)) return true
        }
        return false
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }
}
