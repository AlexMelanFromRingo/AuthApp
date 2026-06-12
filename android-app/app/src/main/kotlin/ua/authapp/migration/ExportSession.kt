package ua.authapp.migration

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.serialization.json.Json
import ua.authapp.crypto.migration.FrameCodec
import ua.authapp.crypto.migration.MigrationCrypto
import ua.authapp.crypto.migration.SealedPackage
import ua.authapp.storage.Token

/**
 * Стан активного експорту (живе лише в пам'яті процесу): потрібен старому
 * пристрою для верифікації квитанції перед штатною деактивацією (FR-018).
 * sealedPackage — snapshot-стан, щоб кнопка «Сканувати квитанцію» на
 * MigrationScreen вмикалася рекомпозицією, а не випадково.
 */
object ExportSession {

    private val json = Json { ignoreUnknownKeys = true }

    var sealedPackage: SealedPackage? by mutableStateOf(null)
        private set
    private var expectedReceipt: ByteArray? = null

    /** Створює пакет із вибраних токенів і повертає QR-кадри. */
    fun start(tokens: List<Token>, passphrase: CharArray): List<String> {
        val manifest = json.encodeToString(TokenManifest.serializer(), TokenManifest(tokens))
            .toByteArray(Charsets.UTF_8)
        val pkg = MigrationCrypto.seal(passphrase, manifest)
        sealedPackage = pkg
        expectedReceipt = MigrationCrypto.receiptMac(passphrase, manifest, pkg)
        return FrameCodec.toFrames(pkg)
    }

    /** Перевіряє відскановану квитанцію з нового пристрою. */
    fun verifyReceipt(receiptUri: String): Boolean {
        val pkg = sealedPackage ?: return false
        val expected = expectedReceipt ?: return false
        val receipt = FrameCodec.parseReceiptUri(receiptUri)
        return receipt.pid == pkg.pid && MigrationCrypto.verifyReceipt(expected, receipt.mac)
    }

    fun clear() {
        expectedReceipt?.fill(0)
        expectedReceipt = null
        sealedPackage = null
    }
}

@kotlinx.serialization.Serializable
data class TokenManifest(val tokens: List<Token>)

/** Відновлення токенів із маніфесту (атомарний імпорт «все або нічого»). */
fun parseManifest(manifestBytes: ByteArray): List<Token> {
    val json = Json { ignoreUnknownKeys = true }
    return json.decodeFromString(TokenManifest.serializer(), manifestBytes.toString(Charsets.UTF_8)).tokens
}
