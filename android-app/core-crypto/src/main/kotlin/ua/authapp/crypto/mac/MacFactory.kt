package ua.authapp.crypto.mac

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.digests.Blake3Digest
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.Blake3Parameters
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Єдина фабрика MAC (contracts/crypto-core.md):
 * - SHA-1/256/512 та SHA3-256 — конструкція HMAC;
 * - BLAKE2s/BLAKE2b/BLAKE3 — нативний keyed-режим (вони спроєктовані як MAC);
 * - секрет, довший за допустимий ключ keyed-режиму, попередньо хешується
 *   тим самим алгоритмом (конвенція, аналогічна HMAC; FR-008).
 *
 * Стандартні HMAC беруться з платформи (javax.crypto), решта — Bouncy Castle.
 * Самописних реалізацій хеш-функцій немає (Конституція, Принцип II).
 */
object MacFactory {

    fun compute(algorithm: HashAlgorithm, key: ByteArray, data: ByteArray): ByteArray =
        when (algorithm) {
            HashAlgorithm.SHA1 -> jcaHmac("HmacSHA1", key, data)
            HashAlgorithm.SHA256 -> jcaHmac("HmacSHA256", key, data)
            HashAlgorithm.SHA512 -> jcaHmac("HmacSHA512", key, data)
            HashAlgorithm.SHA3_256 -> hmacSha3(key, data)
            HashAlgorithm.BLAKE2S_256 -> blake2s(key, data)
            HashAlgorithm.BLAKE2B_512 -> blake2b(key, data)
            HashAlgorithm.BLAKE3_256 -> blake3(key, data)
        }

    private fun jcaHmac(name: String, key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance(name).run {
            init(SecretKeySpec(key, name))
            doFinal(data)
        }

    private fun hmacSha3(key: ByteArray, data: ByteArray): ByteArray {
        val mac = HMac(SHA3Digest(256))
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        return ByteArray(mac.macSize).also { mac.doFinal(it, 0) }
    }

    private fun blake2s(key: ByteArray, data: ByteArray): ByteArray {
        val effectiveKey = if (key.size > 32) plainDigest(Blake2sDigest(256), key) else key
        val digest = Blake2sDigest(effectiveKey, 32, null, null)
        digest.update(data, 0, data.size)
        return ByteArray(digest.digestSize).also { digest.doFinal(it, 0) }
    }

    private fun blake2b(key: ByteArray, data: ByteArray): ByteArray {
        val effectiveKey = if (key.size > 64) plainDigest(Blake2bDigest(512), key) else key
        val digest = Blake2bDigest(effectiveKey, 64, null, null)
        digest.update(data, 0, data.size)
        return ByteArray(digest.digestSize).also { digest.doFinal(it, 0) }
    }

    private fun blake3(key: ByteArray, data: ByteArray): ByteArray {
        // BLAKE3 вимагає ключ рівно 32 байти: інші розміри попередньо хешуються
        val effectiveKey = if (key.size != 32) plainDigest(Blake3Digest(256), key) else key
        val digest = Blake3Digest(256)
        digest.init(Blake3Parameters.key(effectiveKey))
        digest.update(data, 0, data.size)
        return ByteArray(digest.digestSize).also { digest.doFinal(it, 0) }
    }

    private fun plainDigest(digest: org.bouncycastle.crypto.ExtendedDigest, input: ByteArray): ByteArray {
        digest.update(input, 0, input.size)
        return ByteArray(digest.digestSize).also { digest.doFinal(it, 0) }
    }
}
