package ua.authapp.storage

import kotlinx.serialization.Serializable
import ua.authapp.crypto.codec.Base32
import ua.authapp.crypto.codec.ParsedQr
import ua.authapp.crypto.mac.HashAlgorithm
import java.util.UUID

/** Тип токена (data-model.md). */
enum class TokenType { TOTP, OCRA }

/**
 * Збережений токен. Серіалізується в JSON лише всередину
 * EncryptedSharedPreferences — у відкритому вигляді ніколи не існує на диску.
 */
@Serializable
data class Token(
    val id: String = UUID.randomUUID().toString(),
    val type: TokenType,
    val issuer: String,
    val account: String,
    /** Секрет у Base32 (формат обміну; сам файл сховища зашифровано) */
    val secretBase32: String,
    /** Канонічний ідентифікатор алгоритму; для OCRA походить із suite */
    val algorithmId: String = HashAlgorithm.SHA1.id,
    val digits: Int = 6,
    val period: Int = 30,
    /** OCRA-профіль; лише для type == OCRA */
    val ocraSuite: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
) {
    val secret: ByteArray get() = Base32.decode(secretBase32)
    val algorithm: HashAlgorithm
        get() = requireNotNull(HashAlgorithm.fromId(algorithmId)) { "Невідомий алгоритм $algorithmId" }

    /** Збіг параметрів для виявлення дублікатів (edge case специфікації). */
    fun isDuplicateOf(other: Token): Boolean =
        type == other.type && issuer == other.issuer &&
            account == other.account && secretBase32 == other.secretBase32

    companion object {
        fun fromParsed(parsed: ParsedQr): Token = when (parsed) {
            is ParsedQr.TotpToken -> Token(
                type = TokenType.TOTP,
                issuer = parsed.issuer,
                account = parsed.account,
                secretBase32 = Base32.encode(parsed.secret),
                algorithmId = parsed.algorithm.id,
                digits = parsed.digits,
                period = parsed.period,
            )
            is ParsedQr.OcraToken -> Token(
                type = TokenType.OCRA,
                issuer = parsed.issuer,
                account = parsed.account,
                secretBase32 = Base32.encode(parsed.secret),
                ocraSuite = parsed.suite,
            )
            is ParsedQr.OcraChallenge, is ParsedQr.OcraMutualChallenge ->
                throw IllegalArgumentException("QR-код містить виклик, а не токен. Використайте екран OCRA.")
        }
    }
}
