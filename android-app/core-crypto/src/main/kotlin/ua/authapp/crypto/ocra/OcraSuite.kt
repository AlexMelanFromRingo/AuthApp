package ua.authapp.crypto.ocra

import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.mac.HashAlgorithm

/**
 * Підтримуваний OCRA-профіль (RFC 6287 §6; data-model.md):
 * `OCRA-1:HOTP-{SHA1|SHA256|SHA512}-{6|8}:QN08[-T{30S|1M}]`.
 * Лічильник (C), PIN (P) і сесійні дані (S) свідомо поза межами версії
 * (FR-013) — парсер їх відхиляє.
 */
data class OcraSuite(
    /** Повний рядок профілю — входить у DataInput байт-у-байт */
    val raw: String,
    val algorithm: HashAlgorithm,
    val digits: Int,
    /** Крок часу в секундах; null — профіль без часової прив'язки */
    val timeStepSeconds: Int?,
) {
    companion object {

        private val CRYPTO_REGEX = Regex("^HOTP-(SHA1|SHA256|SHA512)-([68])$")
        private val DATA_REGEX = Regex("^QN08(-T(30S|1M))?$")

        fun parse(raw: String): OcraSuite {
            val parts = raw.split(":")
            if (parts.size != 3 || parts[0] != "OCRA-1") {
                throw UriFormatException("Непідтримуваний OCRA-профіль: «$raw»")
            }
            val crypto = CRYPTO_REGEX.matchEntire(parts[1])
                ?: throw UriFormatException(
                    "Підтримуються лише HOTP-SHA1/SHA256/SHA512 із 6 або 8 цифрами, отримано «${parts[1]}»",
                )
            val data = DATA_REGEX.matchEntire(parts[2])
                ?: throw UriFormatException(
                    "Підтримуються лише виклики QN08 з опціональною часовою прив'язкою T30S/T1M, отримано «${parts[2]}»",
                )
            val algorithm = requireNotNull(HashAlgorithm.fromId(crypto.groupValues[1]))
            val timeStep = when (data.groupValues[2]) {
                "" -> null
                "30S" -> 30
                "1M" -> 60
                else -> null
            }
            return OcraSuite(raw, algorithm, crypto.groupValues[2].toInt(), timeStep)
        }
    }
}
