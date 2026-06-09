package ua.authapp.crypto.ocra

import ua.authapp.crypto.mac.MacFactory
import ua.authapp.crypto.truncation.DynamicTruncation
import java.math.BigInteger

/**
 * Обчислення OCRA-відгуку за RFC 6287 (FR-015, contracts/qr-uri-schemes.md §3):
 *
 * DataInput = suite ‖ 0x00 ‖ Q(128 Б) [‖ T(8 Б, big-endian)]
 * Q: десяткове число → hex-рядок (доповнений до парної довжини) → байти,
 *    вирівнювання вліво з доповненням нулями до 128 байтів (RFC §5.1).
 * T: floor(unixTime / крок) — лише для часових профілів.
 *
 * response = усічення(MAC(K, DataInput), digits із профілю).
 */
object Ocra {

    fun computeResponse(
        suite: OcraSuite,
        key: ByteArray,
        question: String,
        unixTimeSeconds: Long? = null,
    ): String {
        require(question.matches(Regex("^\\d{8}$"))) {
            "Виклик має складатися рівно з 8 цифр (профіль QN08)"
        }

        var data = suite.raw.toByteArray(Charsets.US_ASCII) + byteArrayOf(0x00)
        data += encodeQuestion(question)

        suite.timeStepSeconds?.let { step ->
            val time = requireNotNull(unixTimeSeconds) {
                "Часовий профіль ${suite.raw} потребує поточного часу"
            }
            val t = time / step
            val tBytes = ByteArray(8)
            for (i in 0 until 8) {
                tBytes[7 - i] = ((t ushr (i * 8)) and 0xFF).toByte()
            }
            data += tBytes
        }

        val mac = MacFactory.compute(suite.algorithm, key, data)
        return DynamicTruncation.truncate(suite.algorithm, mac, suite.digits).code
    }

    /**
     * Валідація відгуку (стенд/сервер): для часових профілів вікно ±1 крок
     * (FR-015). Порівняння — константним часом.
     */
    fun verifyResponse(
        suite: OcraSuite,
        key: ByteArray,
        question: String,
        response: String,
        unixTimeSeconds: Long? = null,
    ): Boolean {
        val steps = if (suite.timeStepSeconds == null) listOf(0L)
        else listOf(-1L, 0L, 1L).map { it * suite.timeStepSeconds }
        return steps.any { shift ->
            val candidate = computeResponse(
                suite, key, question,
                unixTimeSeconds?.plus(shift),
            )
            constantTimeEquals(candidate, response)
        }
    }

    private fun encodeQuestion(question: String): ByteArray {
        var hex = BigInteger(question).toString(16)
        if (hex.length % 2 == 1) hex += "0"
        val qBytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return qBytes.copyOf(128)
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }
}
