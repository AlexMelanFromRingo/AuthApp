package ua.authapp.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import ua.authapp.crypto.codec.Base32
import ua.authapp.crypto.codec.OtpUri
import ua.authapp.crypto.codec.ParsedQr
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.mac.HashAlgorithm

class CodecTest {

    @Test
    fun `Base32 - кодування і декодування симетричні`() {
        val data = "12345678901234567890".toByteArray()
        assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Base32.encode(data))
        assertArrayEquals(data, Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
        // Толерантність до регістру і пробілів
        assertArrayEquals(data, Base32.decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"))
    }

    @Test
    fun `otpauth - стандартний TOTP розбирається`() {
        val uri = "otpauth://totp/%D0%A1%D1%82%D0%B5%D0%BD%D0%B4:user@example.com" +
            "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=%D0%A1%D1%82%D0%B5%D0%BD%D0%B4" +
            "&algorithm=SHA256&digits=8&period=60"
        val token = OtpUri.parse(uri) as ParsedQr.TotpToken
        assertEquals("Стенд", token.issuer)
        assertEquals("user@example.com", token.account)
        assertEquals(HashAlgorithm.SHA256, token.algorithm)
        assertEquals(8, token.digits)
        assertEquals(60, token.period)
    }

    @Test
    fun `authapp - розширений TOTP із BLAKE3 і 9 цифрами`() {
        val uri = "authapp://totp?v=1&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" +
            "&alg=BLAKE3-256&digits=9&period=30&issuer=Stand&account=demo"
        val token = OtpUri.parse(uri) as ParsedQr.TotpToken
        assertEquals(HashAlgorithm.BLAKE3_256, token.algorithm)
        assertEquals(9, token.digits)
    }

    @Test
    fun `authapp - виклик OCRA розбирається`() {
        val uri = "authapp://ocra-challenge?v=1&suite=OCRA-1:HOTP-SHA256-8:QN08" +
            "&q=48217390&cid=q1w2e3r4&exp=120&label=%D0%A1%D1%82%D0%B5%D0%BD%D0%B4"
        val challenge = OtpUri.parse(uri) as ParsedQr.OcraChallenge
        assertEquals("48217390", challenge.q)
        assertEquals("q1w2e3r4", challenge.cid)
        assertEquals(120, challenge.expSeconds)
        assertEquals("Стенд", challenge.label)
    }

    @Test
    fun `відмови - зрозумілі помилки українською`() {
        // Розширений алгоритм у otpauth:// заборонений
        assertThrows(UriFormatException::class.java) {
            OtpUri.parse("otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ&algorithm=BLAKE3-256")
        }
        // Невідома версія формату
        assertThrows(UriFormatException::class.java) {
            OtpUri.parse("authapp://totp?v=2&secret=GEZDGNBVGY3TQOJQGEZDGNBV&alg=SHA3-256")
        }
        // Закороткий секрет
        assertThrows(UriFormatException::class.java) {
            OtpUri.parse("authapp://totp?v=1&secret=GEZDGNBV&alg=SHA3-256")
        }
        // 10 цифр для стандартного алгоритму заборонені
        assertThrows(UriFormatException::class.java) {
            OtpUri.parse("otpauth://totp/a?secret=GEZDGNBVGY3TQOJQGEZDGNBV&algorithm=SHA1&digits=10")
        }
        // Сміття
        assertThrows(UriFormatException::class.java) { OtpUri.parse("просто текст") }
    }

    @Test
    fun `серіалізація - стандартний у otpauth, розширений у authapp`() {
        val standard = ParsedQr.TotpToken("Стенд", "demo", ByteArray(20) { 1 }, HashAlgorithm.SHA1, 6, 30)
        assert(OtpUri.totpToUri(standard).startsWith("otpauth://totp/"))

        val extended = standard.copy(algorithm = HashAlgorithm.BLAKE2B_512, digits = 10)
        val uri = OtpUri.totpToUri(extended)
        assert(uri.startsWith("authapp://totp?v=1"))
        // Кругова перевірка
        val reparsed = OtpUri.parse(uri) as ParsedQr.TotpToken
        assertEquals(extended.algorithm, reparsed.algorithm)
        assertEquals(extended.digits, reparsed.digits)
        assertArrayEquals(extended.secret, reparsed.secret)
    }
}
