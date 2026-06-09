package ua.authapp.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import ua.authapp.crypto.mac.HashAlgorithm
import ua.authapp.crypto.totp.Totp
import ua.authapp.crypto.truncation.DynamicTruncation
import java.io.File

/**
 * Векторні тести криптоядра (SC-001): 100% кейсів зі спільних векторів
 * shared/test-vectors/ мають проходити без винятків і фільтрів.
 * Вектори згенеровано незалежною Python-реалізацією (R7).
 */
class VectorTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val vectorsDir = File(System.getProperty("vectors.dir")
        ?: error("Системна властивість vectors.dir не задана (див. build.gradle.kts)"))

    @Serializable
    data class TotpCase(
        val alg: String, val secretHex: String, val time: Long,
        val period: Int, val digits: Int, val expected: String,
    )

    @Serializable
    data class TotpFile(val cases: List<TotpCase>)

    @Serializable
    data class TruncationCase(
        val rule: String, val alg: String, val macHex: String,
        val digits: Int, val expectedOffset: Int, val expected: String,
    )

    @Serializable
    data class TruncationFile(val cases: List<TruncationCase>)

    @TestFactory
    fun `вектори TOTP`(): List<DynamicTest> {
        val file = json.decodeFromString<TotpFile>(vectorsDir.resolve("totp.json").readText())
        check(file.cases.isNotEmpty()) { "totp.json порожній" }
        return file.cases.map { case ->
            DynamicTest.dynamicTest("${case.alg} t=${case.time} digits=${case.digits}") {
                val algorithm = requireNotNull(HashAlgorithm.fromId(case.alg)) {
                    "Невідомий алгоритм у векторі: ${case.alg}"
                }
                val actual = Totp.generate(
                    algorithm, case.secretHex.hexToBytes(), case.time, case.period, case.digits,
                )
                assertEquals(case.expected, actual)
            }
        }
    }

    @TestFactory
    fun `вектори динамічного усічення`(): List<DynamicTest> {
        val file = json.decodeFromString<TruncationFile>(vectorsDir.resolve("truncation.json").readText())
        check(file.cases.isNotEmpty()) { "truncation.json порожній" }
        return file.cases.map { case ->
            DynamicTest.dynamicTest("${case.rule} ${case.alg} digits=${case.digits}") {
                val algorithm = requireNotNull(HashAlgorithm.fromId(case.alg))
                val result = DynamicTruncation.truncate(algorithm, case.macHex.hexToBytes(), case.digits)
                assertEquals(case.expectedOffset, result.offset, "offset")
                assertEquals(case.expected, result.code, "код")
            }
        }
    }

    @TestFactory
    fun `інваріант - узагальнене правило тотожне RFC 4226 при L=20`(): List<DynamicTest> {
        // Порівнюємо обидва правила на одному 20-байтовому MAC для digits 6..8
        val mac = ByteArray(20) { (it * 37 + 11).toByte() }
        return (6..8).map { digits ->
            DynamicTest.dynamicTest("digits=$digits") {
                val standard = DynamicTruncation.truncate(HashAlgorithm.SHA1, mac, digits)
                // BLAKE2S-256 тут лише як «носій» узагальненого правила:
                // подаємо той самий 20-байтовий MAC безпосередньо в усічення
                val generalized = DynamicTruncation.truncate(HashAlgorithm.BLAKE2S_256, mac, digits)
                assertEquals(standard.offset, generalized.offset, "offset")
                assertEquals(standard.code, generalized.code, "код")
            }
        }
    }
}

internal fun String.hexToBytes(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
