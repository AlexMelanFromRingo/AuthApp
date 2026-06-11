package ua.authapp.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import ua.authapp.crypto.codec.GoogleAuthMigration
import ua.authapp.crypto.codec.OtpUri
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.mac.HashAlgorithm
import java.io.File

/**
 * Імпорт otpauth-migration (Google Authenticator): вектор згенеровано
 * незалежним Python-кодуванням protobuf (shared/test-vectors/gauth.json).
 */
class GoogleAuthMigrationTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val vectorsDir = File(System.getProperty("vectors.dir")!!)

    @Serializable
    data class ExpectedToken(
        val issuer: String, val account: String,
        val secretHex: String, val alg: String, val digits: Int,
    )

    @Serializable
    data class GauthCase(val uri: String, val skipped: Int, val expected: List<ExpectedToken>)

    @Serializable
    data class GauthFile(val cases: List<GauthCase>)

    @Test
    fun `вектор - розбір експорту з пропуском несумісних записів`() {
        val file = json.decodeFromString<GauthFile>(vectorsDir.resolve("gauth.json").readText())
        for (case in file.cases) {
            val result = GoogleAuthMigration.parse(case.uri)
            assertEquals(case.skipped, result.skipped, "skipped")
            assertEquals(case.expected.size, result.tokens.size, "кількість токенів")
            case.expected.zip(result.tokens).forEach { (expected, actual) ->
                assertEquals(expected.issuer, actual.issuer)
                assertEquals(expected.account, actual.account)
                assertArrayEquals(expected.secretHex.hexToBytes(), actual.secret)
                assertEquals(expected.alg, actual.algorithm.id)
                assertEquals(expected.digits, actual.digits)
                assertEquals(30, actual.period)
            }
        }
    }

    @Test
    fun `відмови - сміття і не-migration URI`() {
        assertThrows<UriFormatException> { GoogleAuthMigration.parse("otpauth://totp/a?secret=GEZDGNBV") }
        assertThrows<UriFormatException> {
            GoogleAuthMigration.parse("otpauth-migration://offline?data=%%%не-base64%%%")
        }
    }

    @Test
    fun `ручне введення - валідація як у QR`() {
        val token = OtpUri.manualTotp(
            issuer = "  Сервіс  ", account = "user@example.com",
            secretBase32 = "gezd gnbv gy3t qojq", // регістр і пробіли толеруються
            algorithm = HashAlgorithm.BLAKE3_256, digits = 9, period = 30,
        )
        assertEquals("Сервіс", token.issuer)
        assertEquals(9, token.digits)
        // 16 символів Base32 = 10 байтів
        assertArrayEquals("1234567890".toByteArray(), token.secret)

        // Закороткий секрет і 10 цифр для SHA1 — відмова
        assertThrows<UriFormatException> {
            OtpUri.manualTotp("a", "b", "GEZDGNBV", HashAlgorithm.SHA1, 6, 30)
        }
        assertThrows<UriFormatException> {
            OtpUri.manualTotp("a", "b", "GEZDGNBVGY3TQOJQGEZDGNBV", HashAlgorithm.SHA1, 10, 30)
        }
    }
}
