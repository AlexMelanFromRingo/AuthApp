package ua.authapp.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.assertThrows
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.mac.HashAlgorithm
import ua.authapp.crypto.ocra.Ocra
import ua.authapp.crypto.ocra.OcraInputs
import ua.authapp.crypto.ocra.OcraSuite
import ua.authapp.crypto.ocra.QuestionFormat
import java.io.File

/**
 * Векторні тести OCRA (SC-002): повний набір RFC 6287 Appendix C —
 * односторонні (включно з C, PSHA1, T), взаємна автентифікація та підпис
 * транзакцій (70 офіційних векторів) + власні T30S/S064.
 */
class OcraVectorTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val vectorsDir = File(System.getProperty("vectors.dir")!!)

    @Serializable
    data class OcraCase(
        val suite: String, val keyHex: String, val q: String,
        val counter: Long? = null, val pinHashHex: String? = null,
        val sessionHex: String? = null, val time: Long? = null,
        val expected: String,
    )

    @Serializable
    data class OcraFile(val cases: List<OcraCase>)

    @TestFactory
    fun `вектори OCRA`(): List<DynamicTest> {
        val file = json.decodeFromString<OcraFile>(vectorsDir.resolve("ocra.json").readText())
        check(file.cases.size >= 70) { "очікувалося ≥70 кейсів, є ${file.cases.size}" }
        return file.cases.mapIndexed { index, case ->
            DynamicTest.dynamicTest("#$index ${case.suite} q=${case.q}") {
                val suite = OcraSuite.parse(case.suite)
                val actual = Ocra.computeResponse(
                    suite, case.keyHex.hexToBytes(),
                    OcraInputs(
                        question = case.q,
                        counter = case.counter,
                        pinHash = case.pinHashHex?.hexToBytes(),
                        sessionInfo = case.sessionHex?.hexToBytes(),
                        unixTimeSeconds = case.time,
                    ),
                )
                assertEquals(case.expected, actual)
            }
        }
    }

    @Test
    fun `хеш PIN - збігається з еталоном RFC`() {
        assertArrayEquals(
            "7110eda4d09e062aa5e4a390b0a572ac0d2c0220".hexToBytes(),
            Ocra.hashPin("1234", HashAlgorithm.SHA1),
        )
    }

    @Test
    fun `верифікація - часове вікно і підроблений відгук`() {
        val suite = OcraSuite.parse("OCRA-1:HOTP-SHA256-8:QN08-T30S")
        val key = "3132333435363738393031323334353637383930313233343536373839303132".hexToBytes()
        val time = 1111111111L
        val inputs = OcraInputs(question = "11111111", unixTimeSeconds = time)
        val valid = Ocra.computeResponse(suite, key, inputs)

        assertTrue(Ocra.verifyResponse(suite, key, inputs.copy(unixTimeSeconds = time + 30), valid))
        assertTrue(Ocra.verifyResponse(suite, key, inputs.copy(unixTimeSeconds = time - 30), valid))
        assertFalse(Ocra.verifyResponse(suite, key, inputs.copy(unixTimeSeconds = time + 120), valid))
        assertFalse(Ocra.verifyResponse(suite, key, inputs, valid.reversed()))
    }

    @Test
    fun `парсер - повна граматика профілю`() {
        val full = OcraSuite.parse("OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1-S064-T1M")
        assertTrue(full.useCounter)
        assertEquals(QuestionFormat.NUMERIC, full.questionFormat)
        assertEquals(8, full.questionLength)
        assertEquals(HashAlgorithm.SHA1, full.pinHashAlgorithm)
        assertEquals(64, full.sessionLength)
        assertEquals(60, full.timeStepSeconds)

        val alpha = OcraSuite.parse("OCRA-1:HOTP-SHA512-8:QA10-T1M")
        assertEquals(QuestionFormat.ALPHANUMERIC, alpha.questionFormat)
        assertEquals(10, alpha.questionLength)
        assertNull(alpha.pinHashAlgorithm)
    }

    @Test
    fun `парсер - відхиляє некоректні профілі`() {
        for (bad in listOf(
            "OCRA-2:HOTP-SHA256-8:QN08",      // невідома версія
            "OCRA-1:HOTP-MD5-6:QN08",         // непідтримуваний хеш
            "OCRA-1:HOTP-SHA256-8:C",         // немає виклику Q
            "OCRA-1:HOTP-SHA256-8:QN08-X064", // невідомий компонент
            "OCRA-1:HOTP-SHA256-8:QZ08",      // невідомий формат виклику
        )) {
            assertThrows<UriFormatException>(bad) { OcraSuite.parse(bad) }
        }
    }

    @Test
    fun `відсутні обовʼязкові входи - зрозумілі помилки`() {
        val key = ByteArray(32) { 1 }
        assertThrows<IllegalArgumentException> {
            Ocra.computeResponse(
                OcraSuite.parse("OCRA-1:HOTP-SHA256-8:C-QN08"), key,
                OcraInputs(question = "12345678"), // немає лічильника
            )
        }
        assertThrows<IllegalArgumentException> {
            Ocra.computeResponse(
                OcraSuite.parse("OCRA-1:HOTP-SHA256-8:QN08-PSHA1"), key,
                OcraInputs(question = "12345678"), // немає PIN
            )
        }
    }
}
