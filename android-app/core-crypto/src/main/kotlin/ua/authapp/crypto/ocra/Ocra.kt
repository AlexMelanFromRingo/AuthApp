package ua.authapp.crypto.ocra

import ua.authapp.crypto.mac.HashAlgorithm
import ua.authapp.crypto.mac.MacFactory
import ua.authapp.crypto.truncation.DynamicTruncation
import java.math.BigInteger
import java.security.MessageDigest

/** Динамічні входи обчислення (відповідно до компонентів профілю). */
data class OcraInputs(
    /** Виклик: для взаємної автентифікації — конкатенація двох викликів */
    val question: String,
    val counter: Long? = null,
    /** Хеш PIN (довжина = розмір дайджесту алгоритму з профілю) */
    val pinHash: ByteArray? = null,
    val sessionInfo: ByteArray? = null,
    val unixTimeSeconds: Long? = null,
)

/**
 * Обчислення OCRA-відгуку за RFC 6287 §5.1 (FR-015, FR-027):
 *
 * DataInput = suite ‖ 0x00 ‖ [C 8Б] ‖ Q(128Б) ‖ [P hash] ‖ [S nnn] ‖ [T 8Б]
 *
 * Кодування Q за форматом: N — десяткове число → hex → байти;
 * A — байти ASCII як є; H — hex → байти; усі — вліво з доповненням до 128 Б.
 * Підтримано односторонні сценарії, взаємну автентифікацію (конкатеновані
 * виклики) та підпис транзакцій. Коректність — на повному наборі векторів
 * RFC 6287 Appendix C (70 векторів).
 */
object Ocra {

    fun computeResponse(suite: OcraSuite, key: ByteArray, inputs: OcraInputs): String {
        var data = suite.raw.toByteArray(Charsets.US_ASCII) + byteArrayOf(0x00)

        if (suite.useCounter) {
            val counter = requireNotNull(inputs.counter) {
                "Профіль ${suite.raw} потребує лічильника"
            }
            data += longTo8Bytes(counter)
        }

        data += encodeQuestion(suite, inputs.question)

        suite.pinHashAlgorithm?.let { pinAlg ->
            val pinHash = requireNotNull(inputs.pinHash) {
                "Профіль ${suite.raw} потребує PIN-коду"
            }
            require(pinHash.size == pinAlg.macLength) {
                "Хеш PIN має бути ${pinAlg.macLength} байтів для ${pinAlg.id}"
            }
            data += pinHash
        }

        suite.sessionLength?.let { length ->
            val session = requireNotNull(inputs.sessionInfo) {
                "Профіль ${suite.raw} потребує сесійних даних"
            }
            data += session.copyOf(length)
        }

        suite.timeStepSeconds?.let { step ->
            val time = requireNotNull(inputs.unixTimeSeconds) {
                "Часовий профіль ${suite.raw} потребує поточного часу"
            }
            data += longTo8Bytes(time / step)
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
        inputs: OcraInputs,
        response: String,
    ): Boolean {
        val shifts = if (suite.timeStepSeconds == null) listOf(0L)
        else listOf(-1L, 0L, 1L).map { it * suite.timeStepSeconds }
        return shifts.any { shift ->
            val candidate = computeResponse(
                suite, key,
                inputs.copy(unixTimeSeconds = inputs.unixTimeSeconds?.plus(shift)),
            )
            constantTimeEquals(candidate, response)
        }
    }

    /** Хеш PIN-коду для P-компонента (платформний MessageDigest). */
    fun hashPin(pin: String, algorithm: HashAlgorithm): ByteArray {
        val digestName = when (algorithm) {
            HashAlgorithm.SHA1 -> "SHA-1"
            HashAlgorithm.SHA256 -> "SHA-256"
            HashAlgorithm.SHA512 -> "SHA-512"
            else -> throw IllegalArgumentException("PIN-хеш підтримує лише SHA-1/256/512")
        }
        return MessageDigest.getInstance(digestName).digest(pin.toByteArray(Charsets.UTF_8))
    }

    private fun encodeQuestion(suite: OcraSuite, question: String): ByteArray {
        val qBytes = when (suite.questionFormat) {
            QuestionFormat.NUMERIC -> {
                require(question.matches(Regex("^\\d+$"))) {
                    "Числовий виклик має складатися лише з цифр"
                }
                var hex = BigInteger(question).toString(16)
                if (hex.length % 2 == 1) hex += "0"
                hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            }
            QuestionFormat.ALPHANUMERIC -> question.toByteArray(Charsets.US_ASCII)
            QuestionFormat.HEX -> {
                val hex = if (question.length % 2 == 1) question + "0" else question
                require(hex.matches(Regex("^[0-9a-fA-F]*$"))) {
                    "Шістнадцятковий виклик містить недопустимі символи"
                }
                hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            }
        }
        require(qBytes.size in 1..128) { "Виклик задовгий: максимум 128 байтів" }
        return qBytes.copyOf(128)
    }

    private fun longTo8Bytes(value: Long): ByteArray {
        val bytes = ByteArray(8)
        for (i in 0 until 8) {
            bytes[7 - i] = ((value ushr (i * 8)) and 0xFF).toByte()
        }
        return bytes
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }
}
