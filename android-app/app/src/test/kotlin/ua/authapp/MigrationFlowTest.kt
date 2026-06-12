package ua.authapp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import ua.authapp.crypto.migration.FrameCodec
import ua.authapp.crypto.migration.MigrationCrypto
import ua.authapp.migration.ExportSession
import ua.authapp.migration.parseManifest
import ua.authapp.storage.Token
import ua.authapp.storage.TokenType

/**
 * Кросс-тест повного протоколу міграції (FR-016..FR-019) на рівні
 * застосунку: ExportSession (старий пристрій) ↔ кадри ↔ збирання,
 * розшифрування і квитанція (новий пристрій) ↔ верифікація квитанції.
 * Симулює польовий сценарій без UI — саме ту послідовність, що замерзала
 * на пристрої через необсервовані стани Compose.
 */
class MigrationFlowTest {

    private val tokens = listOf(
        Token(type = TokenType.TOTP, issuer = "Стенд", account = "demo",
              secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        Token(type = TokenType.OCRA, issuer = "Стенд", account = "ocra",
              secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZD",
              ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08"),
    )

    @BeforeEach
    fun reset() {
        ExportSession.clear()
    }

    @Test
    fun `повний цикл - експорт, кадри не по порядку з повторами, імпорт, квитанція`() {
        val passphrase = "польова-фраза-2026"

        // === Старий пристрій: експорт ===
        val frames = ExportSession.start(tokens, passphrase.toCharArray())
        assertTrue(frames.size >= 2, "очікувалося ≥2 кадри (заголовок + дані)")
        assertNotNull(ExportSession.sealedPackage, "кнопка квитанції має бути активною")

        // === Новий пристрій: збирання з повторами і не по порядку ===
        val assembler = FrameCodec.FrameAssembler()
        // двічі кадр 1 (сценарій користувача) — другий раз ігнорується
        assertTrue(assembler.accept(frames[0]))
        assertFalse(assembler.accept(frames[0]))
        assertEquals(1, assembler.receivedCount)
        // решта у зворотному порядку
        frames.drop(1).reversed().forEach { assertTrue(assembler.accept(it)) }
        assertTrue(assembler.isComplete)

        // === Розшифрування і відновлення токенів ===
        val pkg = assembler.assemble()
        val manifest = MigrationCrypto.open(passphrase.toCharArray(), pkg)
        val restored = parseManifest(manifest)
        assertEquals(tokens.size, restored.size)
        assertEquals(tokens[0].secretBase32, restored[0].secretBase32)
        assertEquals(tokens[1].ocraSuite, restored[1].ocraSuite)

        // === Квитанція: новий пристрій формує, старий верифікує ===
        val receiptUri = FrameCodec.receiptUri(
            pkg.pid,
            MigrationCrypto.receiptMac(passphrase.toCharArray(), manifest, pkg),
        )
        assertTrue(ExportSession.verifyReceipt(receiptUri), "квитанція має пройти")
    }

    @Test
    fun `квитанція - підробка MAC і чужий pid відхиляються`() {
        val passphrase = "фраза"
        val frames = ExportSession.start(tokens, passphrase.toCharArray())
        val assembler = FrameCodec.FrameAssembler()
        frames.forEach(assembler::accept)
        val pkg = assembler.assemble()
        val manifest = MigrationCrypto.open(passphrase.toCharArray(), pkg)
        val mac = MigrationCrypto.receiptMac(passphrase.toCharArray(), manifest, pkg)

        // Підроблений MAC
        val forgedMac = mac.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(ExportSession.verifyReceipt(FrameCodec.receiptUri(pkg.pid, forgedMac)))

        // Правильний MAC, але чужий pid (квитанція від іншого експорту)
        assertFalse(ExportSession.verifyReceipt(FrameCodec.receiptUri("інший-pid", mac)))

        // Після clear() жодна квитанція не приймається
        ExportSession.clear()
        assertFalse(ExportSession.verifyReceipt(FrameCodec.receiptUri(pkg.pid, mac)))
    }
}
