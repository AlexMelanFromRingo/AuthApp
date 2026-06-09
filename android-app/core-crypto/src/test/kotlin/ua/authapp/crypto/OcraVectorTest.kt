package ua.authapp.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.assertThrows
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.ocra.Ocra
import ua.authapp.crypto.ocra.OcraSuite
import java.io.File

/**
 * Векторні тести OCRA (SC-002): спільні вектори shared/test-vectors/ocra.json
 * (включно з офіційними RFC 6287 Appendix C.1) — 100% зелені.
 */
class OcraVectorTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val vectorsDir = File(System.getProperty("vectors.dir")!!)

    @Serializable
    data class OcraCase(
        val suite: String, val keyHex: String, val q: String,
        val time: Long? = null, val expected: String,
    )

    @Serializable
    data class OcraFile(val cases: List<OcraCase>)

    @TestFactory
    fun `вектори OCRA`(): List<DynamicTest> {
        val file = json.decodeFromString<OcraFile>(vectorsDir.resolve("ocra.json").readText())
        check(file.cases.isNotEmpty()) { "ocra.json порожній" }
        return file.cases.map { case ->
            DynamicTest.dynamicTest("${case.suite} q=${case.q}") {
                val suite = OcraSuite.parse(case.suite)
                val actual = Ocra.computeResponse(suite, case.keyHex.hexToBytes(), case.q, case.time)
                assertEquals(case.expected, actual)
            }
        }
    }

    @Test
    fun `верифікація - часове вікно і підроблений відгук`() {
        val suite = OcraSuite.parse("OCRA-1:HOTP-SHA256-8:QN08-T30S")
        val key = "3132333435363738393031323334353637383930313233343536373839303132".hexToBytes()
        val time = 1111111111L
        val valid = Ocra.computeResponse(suite, key, "11111111", time)

        // Зсув годинника на ±1 крок приймається
        assertTrue(Ocra.verifyResponse(suite, key, "11111111", valid, time + 30))
        assertTrue(Ocra.verifyResponse(suite, key, "11111111", valid, time - 30))
        // Понад вікно або підробка — відмова
        assertFalse(Ocra.verifyResponse(suite, key, "11111111", valid, time + 120))
        assertFalse(Ocra.verifyResponse(suite, key, "11111111", valid.reversed(), time))
    }

    @Test
    fun `парсер - відхиляє непідтримувані профілі`() {
        // Лічильник, PIN, сесія, буквені виклики — поза межами версії (FR-013)
        for (bad in listOf(
            "OCRA-1:HOTP-SHA256-8:C-QN08",
            "OCRA-1:HOTP-SHA256-8:QN08-PSHA1",
            "OCRA-1:HOTP-SHA256-8:QA10",
            "OCRA-1:HOTP-SHA256-8:QN08-S064",
            "OCRA-2:HOTP-SHA256-8:QN08",
            "OCRA-1:HOTP-MD5-6:QN08",
        )) {
            assertThrows<UriFormatException>(bad) { OcraSuite.parse(bad) }
        }
    }
}
