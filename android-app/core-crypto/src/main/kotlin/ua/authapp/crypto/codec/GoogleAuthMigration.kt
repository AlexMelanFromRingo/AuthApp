package ua.authapp.crypto.codec

import ua.authapp.crypto.mac.HashAlgorithm
import java.net.URLDecoder

/**
 * Імпорт експортних QR-кодів Google Authenticator:
 * `otpauth-migration://offline?data=<base64(protobuf MigrationPayload)>`.
 *
 * Схема MigrationPayload (зворотно розібраний відкритий формат GA):
 *   1: repeated OtpParameters { 1: secret(bytes), 2: name, 3: issuer,
 *      4: algorithm(1=SHA1,2=SHA256,3=SHA512,4=MD5), 5: digits(1=6,2=8),
 *      6: type(1=HOTP,2=TOTP), 7: counter }
 *   2: version, 3: batch_size, 4: batch_index, 5: batch_id
 *
 * Несумісні записи (HOTP, MD5, недопустимий секрет) пропускаються з
 * підрахунком — імпорт не зривається через один поганий запис.
 */
object GoogleAuthMigration {

    data class ImportResult(
        val tokens: List<ParsedQr.TotpToken>,
        /** Кількість пропущених несумісних записів */
        val skipped: Int,
        val batchIndex: Int,
        val batchSize: Int,
    )

    fun isMigrationUri(raw: String): Boolean =
        raw.trim().startsWith("otpauth-migration://")

    fun parse(raw: String): ImportResult {
        val match = Regex("^otpauth-migration://offline\\?data=(.+)$").matchEntire(raw.trim())
            ?: throw UriFormatException("QR-код не є експортом Google Authenticator")
        val payload = try {
            // URL-декодер перетворює «+» на пробіл — повертаємо назад для Base64
            val b64 = URLDecoder.decode(match.groupValues[1], Charsets.UTF_8).replace(' ', '+')
            java.util.Base64.getDecoder().decode(b64)
        } catch (e: IllegalArgumentException) {
            throw UriFormatException("Пошкоджені дані експорту Google Authenticator")
        }

        val tokens = ArrayList<ParsedQr.TotpToken>()
        var skipped = 0
        var batchIndex = 0
        var batchSize = 1

        val reader = ProtobufReader(payload)
        while (reader.hasMore()) {
            val tag = reader.readVarint().toInt()
            when (val field = tag ushr 3) {
                1 -> {
                    val parsed = parseOtpParameters(reader.readBytes())
                    if (parsed != null) tokens += parsed else skipped++
                }
                3 -> batchSize = reader.readVarint().toInt()
                4 -> batchIndex = reader.readVarint().toInt()
                else -> reader.skip(tag and 7)
            }
        }
        if (tokens.isEmpty() && skipped == 0) {
            throw UriFormatException("Експорт Google Authenticator не містить токенів")
        }
        return ImportResult(tokens, skipped, batchIndex, batchSize)
    }

    /** @return токен або null, якщо запис несумісний (пропускається) */
    private fun parseOtpParameters(message: ByteArray): ParsedQr.TotpToken? {
        var secret = ByteArray(0)
        var name = ""
        var issuer = ""
        var algorithm = 1
        var digits = 1
        var type = 2

        val reader = ProtobufReader(message)
        while (reader.hasMore()) {
            val tag = reader.readVarint().toInt()
            when (tag ushr 3) {
                1 -> secret = reader.readBytes()
                2 -> name = reader.readBytes().toString(Charsets.UTF_8)
                3 -> issuer = reader.readBytes().toString(Charsets.UTF_8)
                4 -> algorithm = reader.readVarint().toInt()
                5 -> digits = reader.readVarint().toInt()
                6 -> type = reader.readVarint().toInt()
                else -> reader.skip(tag and 7)
            }
        }

        val hashAlgorithm = when (algorithm) {
            0, 1 -> HashAlgorithm.SHA1
            2 -> HashAlgorithm.SHA256
            3 -> HashAlgorithm.SHA512
            else -> return null // MD5 та невідомі — не підтримуються
        }
        if (type != 2) return null            // лише TOTP; HOTP пропускається
        if (secret.size !in 10..64) return null
        val digitCount = when (digits) {
            0, 1 -> 6
            2 -> 8
            else -> return null
        }

        // GA часто кладе «issuer:account» у name; розплутуємо
        val account = name.substringAfter(':', name).trim()
        val effectiveIssuer = issuer.ifBlank { name.substringBefore(':', "").trim() }

        return ParsedQr.TotpToken(
            issuer = effectiveIssuer.ifBlank { "Без назви" },
            account = account,
            secret = secret,
            algorithm = hashAlgorithm,
            digits = digitCount,
            period = 30, // фіксований період Google Authenticator
        )
    }
}

/** Мінімальний декодер protobuf wire-format (varint + length-delimited). */
internal class ProtobufReader(private val data: ByteArray) {

    private var pos = 0

    fun hasMore(): Boolean = pos < data.size

    fun readVarint(): Long {
        var shift = 0
        var result = 0L
        while (true) {
            if (pos >= data.size || shift > 63) {
                throw UriFormatException("Пошкоджені дані експорту Google Authenticator")
            }
            val byte = data[pos++].toInt()
            result = result or ((byte.toLong() and 0x7F) shl shift)
            if (byte and 0x80 == 0) return result
            shift += 7
        }
    }

    fun readBytes(): ByteArray {
        val length = readVarint().toInt()
        if (length < 0 || pos + length > data.size) {
            throw UriFormatException("Пошкоджені дані експорту Google Authenticator")
        }
        return data.copyOfRange(pos, pos + length).also { pos += length }
    }

    fun skip(wireType: Int) {
        when (wireType) {
            0 -> readVarint()
            1 -> pos += 8
            2 -> readBytes()
            5 -> pos += 4
            else -> throw UriFormatException("Пошкоджені дані експорту Google Authenticator")
        }
    }
}
