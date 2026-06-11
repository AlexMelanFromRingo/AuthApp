package ua.authapp.crypto.ocra

import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.mac.HashAlgorithm

/** Формат виклику Q (RFC 6287 §6): числовий, буквено-цифровий, шістнадцятковий. */
enum class QuestionFormat { NUMERIC, ALPHANUMERIC, HEX }

/**
 * Повний OCRA-профіль за RFC 6287 §6 (FR-027):
 * `OCRA-1:HOTP-{SHA1|SHA256|SHA512}-{6|8}:[C-]Q{N|A|H}{04..64}[-PSHA{1|256|512}][-S{nnn}][-T{n}{S|M|H}]`
 *
 * Підтримано всі компоненти DataInput: лічильник C, виклик Q (включно з
 * конкатенованими викликами взаємної автентифікації та підписом транзакцій),
 * PIN-хеш P, сесійні дані S, часова прив'язка T.
 */
data class OcraSuite(
    /** Повний рядок профілю — входить у DataInput байт-у-байт */
    val raw: String,
    val algorithm: HashAlgorithm,
    val digits: Int,
    /** Профіль містить 8-байтовий лічильник C */
    val useCounter: Boolean,
    val questionFormat: QuestionFormat,
    /** Декларована довжина одного виклику (для взаємної автентифікації Q — конкатенація двох) */
    val questionLength: Int,
    /** Алгоритм хешу PIN (PSHA1/...); null — без PIN */
    val pinHashAlgorithm: HashAlgorithm?,
    /** Довжина сесійних даних у байтах (Snnn); null — без сесії */
    val sessionLength: Int?,
    /** Крок часу в секундах; null — без часової прив'язки */
    val timeStepSeconds: Int?,
) {
    companion object {

        private val CRYPTO_REGEX = Regex("^HOTP-(SHA1|SHA256|SHA512)-([68])$")
        private val QUESTION_REGEX = Regex("^Q([NAH])(\\d{2})$")
        private val PIN_REGEX = Regex("^PSHA(1|256|512)$")
        private val SESSION_REGEX = Regex("^S(\\d{3})$")
        private val TIME_REGEX = Regex("^T(\\d{1,2})([SMH])$")

        fun parse(raw: String): OcraSuite {
            val parts = raw.split(":")
            if (parts.size != 3 || parts[0] != "OCRA-1") {
                throw UriFormatException("Непідтримуваний OCRA-профіль: «$raw»")
            }
            val crypto = CRYPTO_REGEX.matchEntire(parts[1])
                ?: throw UriFormatException(
                    "Підтримуються лише HOTP-SHA1/SHA256/SHA512 із 6 або 8 цифрами, отримано «${parts[1]}»",
                )
            val algorithm = requireNotNull(HashAlgorithm.fromId(crypto.groupValues[1]))

            // DataInput: [C-]QXnn[-PSHAx][-Snnn][-Tnu] — суворо в цьому порядку
            var components = parts[2].split("-")
            var useCounter = false
            if (components.firstOrNull() == "C") {
                useCounter = true
                components = components.drop(1)
            }

            val question = components.firstOrNull()?.let { QUESTION_REGEX.matchEntire(it) }
                ?: throw UriFormatException("OCRA-профіль має містити виклик Q: «${parts[2]}»")
            val questionFormat = when (question.groupValues[1]) {
                "N" -> QuestionFormat.NUMERIC
                "A" -> QuestionFormat.ALPHANUMERIC
                else -> QuestionFormat.HEX
            }
            val questionLength = question.groupValues[2].toInt()
            if (questionLength !in 4..64) {
                throw UriFormatException("Довжина виклику має бути 04..64, отримано $questionLength")
            }
            components = components.drop(1)

            var pinHashAlgorithm: HashAlgorithm? = null
            var sessionLength: Int? = null
            var timeStepSeconds: Int? = null
            for (component in components) {
                val pin = PIN_REGEX.matchEntire(component)
                val session = SESSION_REGEX.matchEntire(component)
                val time = TIME_REGEX.matchEntire(component)
                when {
                    pin != null -> pinHashAlgorithm =
                        requireNotNull(HashAlgorithm.fromId("SHA" + pin.groupValues[1]))
                    session != null -> sessionLength = session.groupValues[1].toInt()
                    time != null -> {
                        val unit = when (time.groupValues[2]) {
                            "S" -> 1
                            "M" -> 60
                            else -> 3600
                        }
                        timeStepSeconds = time.groupValues[1].toInt() * unit
                    }
                    else -> throw UriFormatException("Невідомий компонент OCRA-профілю: «$component»")
                }
            }

            return OcraSuite(
                raw = raw,
                algorithm = algorithm,
                digits = crypto.groupValues[2].toInt(),
                useCounter = useCounter,
                questionFormat = questionFormat,
                questionLength = questionLength,
                pinHashAlgorithm = pinHashAlgorithm,
                sessionLength = sessionLength,
                timeStepSeconds = timeStepSeconds,
            )
        }
    }
}
