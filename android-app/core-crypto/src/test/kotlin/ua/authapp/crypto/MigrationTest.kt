package ua.authapp.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import ua.authapp.crypto.migration.FrameCodec
import ua.authapp.crypto.migration.KdfParams
import ua.authapp.crypto.migration.MigrationCrypto
import ua.authapp.crypto.migration.MigrationOpenException

/**
 * Тести протоколу міграції (FR-016..FR-019): round-trip, відмова за
 * неправильної фрази, квитанція, кадрування з дозбиранням.
 * KDF у тестах — зі зменшеною пам'яттю (16 МіБ), щоб не сповільнювати CI;
 * продакшн-константи (64 МіБ) перевіряються окремим повільним кейсом за
 * потреби на пристрої.
 */
class MigrationTest {

    private val testKdf = KdfParams(memoryKib = 16384, iterations = 2, parallelism = 2)
    private val manifest = """{"tokens":[{"issuer":"Стенд","secret":"GEZDGNBV"}]}"""
        .toByteArray()

    @Test
    fun `round-trip - експорт і імпорт відновлюють маніфест`() {
        val pkg = MigrationCrypto.seal("кохана-фраза-123".toCharArray(), manifest, testKdf)
        val restored = MigrationCrypto.open("кохана-фраза-123".toCharArray(), pkg)
        assertArrayEquals(manifest, restored)
    }

    @Test
    fun `неправильна фраза - відмова без розкриття деталей`() {
        val pkg = MigrationCrypto.seal("правильна".toCharArray(), manifest, testKdf)
        assertThrows<MigrationOpenException> {
            MigrationCrypto.open("неправильна".toCharArray(), pkg)
        }
    }

    @Test
    fun `пошкоджений шифротекст - відмова`() {
        val pkg = MigrationCrypto.seal("фраза".toCharArray(), manifest, testKdf)
        pkg.ciphertext[pkg.ciphertext.size / 2] =
            (pkg.ciphertext[pkg.ciphertext.size / 2].toInt() xor 0x01).toByte()
        assertThrows<MigrationOpenException> {
            MigrationCrypto.open("фраза".toCharArray(), pkg)
        }
    }

    @Test
    fun `квитанція - збігається в обох сторін і ламається від підробки`() {
        val passphrase = "спільна-фраза"
        val pkg = MigrationCrypto.seal(passphrase.toCharArray(), manifest, testKdf)

        // Новий пристрій обчислює квитанцію після успішного імпорту
        val restored = MigrationCrypto.open(passphrase.toCharArray(), pkg)
        val receiptFromNew = MigrationCrypto.receiptMac(passphrase.toCharArray(), restored, pkg)

        // Старий пристрій знає очікуваний MAC зі свого маніфесту
        val expected = MigrationCrypto.receiptMac(passphrase.toCharArray(), manifest, pkg)
        assertTrue(MigrationCrypto.verifyReceipt(expected, receiptFromNew))

        // Підробка хоч одного байта — провал верифікації
        val forged = receiptFromNew.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertFalse(MigrationCrypto.verifyReceipt(expected, forged))
    }

    @Test
    fun `кадри - розбирання у довільному порядку і дозбирання пропущених`() {
        // Великий маніфест → гарантовано кілька кадрів
        val bigManifest = manifest + ByteArray(1500) { (it % 251).toByte() }
        val pkg = MigrationCrypto.seal("фраза".toCharArray(), bigManifest, testKdf)
        val frames = FrameCodec.toFrames(pkg)
        assertTrue(frames.size >= 4, "очікувалося ≥4 кадри, отримано ${frames.size}")

        val assembler = FrameCodec.FrameAssembler()
        // Подаємо в перемішаному порядку, «гублячи» кадр 2
        val shuffled = frames.shuffled(java.util.Random(42)).filterIndexed { i, _ -> i != 0 }
        val lost = frames.toSet() - shuffled.toSet()
        shuffled.forEach { assembler.accept(it) }

        assertFalse(assembler.isComplete)
        assertEquals(1, assembler.missingFrames().size)

        // Повторний кадр ігнорується, дозбирання завершує пакет
        assertFalse(assembler.accept(shuffled.first()))
        lost.forEach { assembler.accept(it) }
        assertTrue(assembler.isComplete)

        val reassembled = assembler.assemble()
        assertArrayEquals(pkg.ciphertext, reassembled.ciphertext)
        assertArrayEquals(
            bigManifest,
            MigrationCrypto.open("фраза".toCharArray(), reassembled),
        )
    }

    @Test
    fun `кадри - повторне сканування того самого кадру не змінює прогрес`() {
        // Регресія польового прогону: користувач двічі сканує кадр 1 —
        // лічильник не повинен зрости і пакет не повинен «завершитися»
        val pkg = MigrationCrypto.seal("фраза".toCharArray(), manifest, testKdf)
        val frames = FrameCodec.toFrames(pkg)
        assertTrue(frames.size >= 2)

        val assembler = FrameCodec.FrameAssembler()
        assertTrue(assembler.accept(frames[0]))
        assertEquals(1, assembler.receivedCount)
        // Повтор того самого кадру — false, стан незмінний
        assertFalse(assembler.accept(frames[0]))
        assertEquals(1, assembler.receivedCount)
        assertFalse(assembler.isComplete)
        assertEquals((2..frames.size).toList(), assembler.missingFrames())

        // Дозбирання решти кадрів завершує пакет рівно один раз
        frames.drop(1).forEach { assembler.accept(it) }
        assertTrue(assembler.isComplete)
        assertEquals(frames.size, assembler.receivedCount)
    }

    @Test
    fun `кадри - чужий пакет ігнорується`() {
        val pkgA = MigrationCrypto.seal("a".toCharArray(), manifest, testKdf)
        val pkgB = MigrationCrypto.seal("b".toCharArray(), manifest, testKdf)
        val assembler = FrameCodec.FrameAssembler()
        assertTrue(assembler.accept(FrameCodec.toFrames(pkgA)[0]))
        assertFalse(assembler.accept(FrameCodec.toFrames(pkgB)[0]))
    }

    @Test
    fun `квитанція - серіалізація URI кругова`() {
        val mac = ByteArray(32) { it.toByte() }
        val uri = FrameCodec.receiptUri("abc123", mac)
        val parsed = FrameCodec.parseReceiptUri(uri)
        assertEquals("abc123", parsed.pid)
        assertArrayEquals(mac, parsed.mac)
    }
}
