package ua.authapp.crypto.migration

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.HKDFParameters
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Невірна парольна фраза або пошкоджений/підроблений пакет (FR-017). */
class MigrationOpenException :
    Exception("Неправильна парольна фраза або пошкоджений пакет")

/** Параметри Argon2id; продакшн-константи з R5 (m=64 МіБ, t=3, p=4). */
data class KdfParams(val memoryKib: Int = 65536, val iterations: Int = 3, val parallelism: Int = 4)

/** Захищений пакет міграції (data-model.md: MigrationPackage). */
data class SealedPackage(
    val pid: String,
    val version: Int,
    val salt: ByteArray,
    val kdfParams: KdfParams,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
)

/**
 * Криптографія міграції (FR-016, FR-018, R5):
 *
 * master = Argon2id(passphrase, salt) → 64 Б
 * K_enc  = HKDF-SHA256(master, info="authapp-migration-enc") → 32 Б
 * K_rcpt = HKDF-SHA256(master, info="authapp-migration-receipt") → 32 Б
 * пакет  = AES-256-GCM(K_enc, nonce, маніфест)
 * квитанція = HMAC-SHA256(K_rcpt, SHA-256(маніфест) ‖ nonce)
 *
 * GCM автентифікує пакет: неправильна фраза чи будь-яке пошкодження →
 * [MigrationOpenException] без часткового розшифрування.
 */
object MigrationCrypto {

    const val FORMAT_VERSION = 1

    private val random = SecureRandom()

    fun seal(
        passphrase: CharArray,
        manifest: ByteArray,
        kdfParams: KdfParams = KdfParams(),
    ): SealedPackage {
        val salt = ByteArray(16).also(random::nextBytes)
        val nonce = ByteArray(12).also(random::nextBytes)
        val pid = Base64Url.encode(ByteArray(8).also(random::nextBytes))
        val keys = deriveKeys(passphrase, salt, kdfParams)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(keys.encryption, "AES"),
                GCMParameterSpec(128, nonce),
            )
            return SealedPackage(pid, FORMAT_VERSION, salt, kdfParams, nonce, cipher.doFinal(manifest))
        } finally {
            keys.destroy()
        }
    }

    fun open(passphrase: CharArray, pkg: SealedPackage): ByteArray {
        if (pkg.version != FORMAT_VERSION) {
            throw MigrationOpenException()
        }
        val keys = deriveKeys(passphrase, pkg.salt, pkg.kdfParams)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(keys.encryption, "AES"),
                GCMParameterSpec(128, pkg.nonce),
            )
            return cipher.doFinal(pkg.ciphertext)
        } catch (e: Exception) {
            // GCM-тег не зійшовся: фраза невірна або пакет пошкоджено —
            // деталі не розкриваємо (FR-017)
            throw MigrationOpenException()
        } finally {
            keys.destroy()
        }
    }

    /** Квитанція імпорту (FR-018): MAC від маніфесту на ключі K_rcpt. */
    fun receiptMac(
        passphrase: CharArray,
        manifest: ByteArray,
        pkg: SealedPackage,
    ): ByteArray {
        val keys = deriveKeys(passphrase, pkg.salt, pkg.kdfParams)
        try {
            val manifestHash = MessageDigest.getInstance("SHA-256").digest(manifest)
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(keys.receipt, "HmacSHA256"))
            mac.update(manifestHash)
            mac.update(pkg.nonce)
            return mac.doFinal()
        } finally {
            keys.destroy()
        }
    }

    /** Верифікація квитанції на старому пристрої — константним часом. */
    fun verifyReceipt(expectedMac: ByteArray, receivedMac: ByteArray): Boolean =
        MessageDigest.isEqual(expectedMac, receivedMac)

    // -- Виведення ключів ----------------------------------------------------

    private class DerivedKeys(val encryption: ByteArray, val receipt: ByteArray) {
        /** Зануляння ключового матеріалу після операції (T039) */
        fun destroy() {
            encryption.fill(0)
            receipt.fill(0)
        }
    }

    private fun deriveKeys(passphrase: CharArray, salt: ByteArray, params: KdfParams): DerivedKeys {
        val generator = Argon2BytesGenerator()
        generator.init(
            Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withMemoryAsKB(params.memoryKib)
                .withIterations(params.iterations)
                .withParallelism(params.parallelism)
                .build(),
        )
        val master = ByteArray(64)
        generator.generateBytes(passphrase, master)

        val keys = DerivedKeys(
            encryption = hkdf(master, "authapp-migration-enc"),
            receipt = hkdf(master, "authapp-migration-receipt"),
        )
        master.fill(0)
        return keys
    }

    private fun hkdf(master: ByteArray, info: String): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(master, null, info.toByteArray(Charsets.US_ASCII)))
        return ByteArray(32).also { generator.generateBytes(it, 0, it.size) }
    }
}

/** Base64url без паддінгу (формат бінарних значень у URI). */
object Base64Url {
    fun encode(data: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    fun decode(text: String): ByteArray =
        java.util.Base64.getUrlDecoder().decode(text)
}
