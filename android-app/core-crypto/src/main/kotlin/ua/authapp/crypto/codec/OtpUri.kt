package ua.authapp.crypto.codec

import ua.authapp.crypto.mac.HashAlgorithm
import java.net.URLDecoder
import java.net.URLEncoder

/** Помилка формату QR-коду з україномовним поясненням для користувача (FR-006). */
class UriFormatException(message: String) : IllegalArgumentException(message)

/** Розібраний вміст QR-коду (contracts/qr-uri-schemes.md). */
sealed interface ParsedQr {

    data class TotpToken(
        val issuer: String,
        val account: String,
        val secret: ByteArray,
        val algorithm: HashAlgorithm,
        val digits: Int,
        val period: Int,
    ) : ParsedQr

    data class OcraToken(
        val issuer: String,
        val account: String,
        val secret: ByteArray,
        val suite: String,
    ) : ParsedQr

    data class OcraChallenge(
        val suite: String,
        val q: String,
        val cid: String,
        val expSeconds: Int,
        val label: String?,
        /** Значення лічильника для C-профілів (синхронізує сервер) */
        val counter: Long? = null,
        /** Сесійні дані для S-профілів (base64url) */
        val sessionB64: String? = null,
        /** "sign" — підпис транзакції (q = дані транзакції) */
        val mode: String? = null,
    ) : ParsedQr

    /** Взаємна автентифікація (RFC 6287 §7.2): клієнт спершу перевіряє сервер. */
    data class OcraMutualChallenge(
        /** Профіль обчислення клієнта (= профіль токена) */
        val clientSuite: String,
        /** Профіль обчислення сервера */
        val serverSuite: String,
        /** Виклик клієнта QC */
        val qc: String,
        /** Виклик сервера QS */
        val qs: String,
        /** Відгук сервера = OCRA(K, Q = QC ‖ QS) — клієнт верифікує */
        val serverResponse: String,
        val cid: String,
        val expSeconds: Int,
        val label: String?,
    ) : ParsedQr
}

/**
 * Парсер і серіалізатор URI-схем QR-кодів:
 * - `otpauth://totp/...` — стандартні TOTP (сумісність зі сторонніми додатками);
 * - `authapp://totp` — розширені алгоритми (v=1);
 * - `authapp://ocra-token`, `authapp://ocra-challenge` — OCRA.
 *
 * Невідома версія, відсутні обов'язкові параметри чи недопустимі значення →
 * [UriFormatException] зі зрозумілим поясненням (FR-006).
 */
object OtpUri {

    private const val SUPPORTED_VERSION = "1"
    private val URI_REGEX = Regex("^([a-z]+)://([a-z-]+)(/[^?]*)?(?:\\?(.*))?$")

    fun parse(raw: String): ParsedQr {
        val match = URI_REGEX.matchEntire(raw.trim())
            ?: throw UriFormatException("QR-код не містить підтримуваного URI")
        val (scheme, host, rawPath, rawQuery) = match.destructured
        val params = parseQuery(rawQuery)

        return when {
            scheme == "otpauth" && host == "totp" -> parseOtpauthTotp(rawPath, params)
            scheme == "authapp" -> {
                checkVersion(params)
                when (host) {
                    "totp" -> parseAuthappTotp(params)
                    "ocra-token" -> parseOcraToken(params)
                    "ocra-challenge" -> parseOcraChallenge(params)
                    "ocra-mutual" -> parseOcraMutual(params)
                    else -> throw UriFormatException("Невідомий тип QR-коду: «$host»")
                }
            }
            else -> throw UriFormatException("Схема «$scheme://$host» не підтримується")
        }
    }

    // -- Серіалізація (використовується стендом через спільний контракт, а в
    //    додатку — для квитанцій і повторного показу QR) -------------------

    fun totpToUri(token: ParsedQr.TotpToken): String {
        val secret = Base32.encode(token.secret)
        return if (!token.algorithm.isExtended && token.digits <= 8) {
            val label = encode("${token.issuer}:${token.account}")
            "otpauth://totp/$label?secret=$secret&issuer=${encode(token.issuer)}" +
                "&algorithm=${token.algorithm.id}&digits=${token.digits}&period=${token.period}"
        } else {
            "authapp://totp?v=1&secret=$secret&alg=${token.algorithm.id}" +
                "&digits=${token.digits}&period=${token.period}" +
                "&issuer=${encode(token.issuer)}&account=${encode(token.account)}"
        }
    }

    /**
     * Ручне введення секрету (аналог «Введіть ключ налаштування» у Google
     * Authenticator): та сама валідація, що й для QR (FR-006).
     */
    fun manualTotp(
        issuer: String,
        account: String,
        secretBase32: String,
        algorithm: HashAlgorithm,
        digits: Int,
        period: Int,
    ): ParsedQr.TotpToken {
        val params = mapOf(
            "secret" to secretBase32,
            "digits" to digits.toString(),
            "period" to period.toString(),
        )
        return ParsedQr.TotpToken(
            issuer = issuer.trim().ifBlank { "Без назви" },
            account = account.trim(),
            secret = requireSecret(params),
            algorithm = algorithm,
            digits = requireDigits(params, max = if (algorithm.isExtended) 10 else 8),
            period = requirePeriod(params),
        )
    }

    // -- Розбір окремих форматів ------------------------------------------

    private fun parseOtpauthTotp(rawPath: String, params: Map<String, String>): ParsedQr.TotpToken {
        val label = decode(rawPath.removePrefix("/"))
        val (labelIssuer, account) = splitLabel(label)
        val issuer = params["issuer"] ?: labelIssuer
        val algorithm = (params["algorithm"] ?: "SHA1").let {
            HashAlgorithm.fromId(it) ?: throw UriFormatException("Алгоритм «$it» не підтримується")
        }
        if (algorithm.isExtended) {
            throw UriFormatException("Розширені алгоритми передаються схемою authapp://, а не otpauth://")
        }
        return ParsedQr.TotpToken(
            issuer = issuer.ifBlank { "Без назви" },
            account = account,
            secret = requireSecret(params),
            algorithm = algorithm,
            digits = requireDigits(params, max = 8),
            period = requirePeriod(params),
        )
    }

    private fun parseAuthappTotp(params: Map<String, String>): ParsedQr.TotpToken {
        val algorithmId = params["alg"]
            ?: throw UriFormatException("У QR-коді відсутній параметр алгоритму (alg)")
        val algorithm = HashAlgorithm.fromId(algorithmId)
            ?: throw UriFormatException("Алгоритм «$algorithmId» не підтримується")
        return ParsedQr.TotpToken(
            issuer = params["issuer"]?.ifBlank { null } ?: "Без назви",
            account = params["account"] ?: "",
            secret = requireSecret(params),
            algorithm = algorithm,
            digits = requireDigits(params, max = if (algorithm.isExtended) 10 else 8),
            period = requirePeriod(params),
        )
    }

    private fun parseOcraToken(params: Map<String, String>): ParsedQr.OcraToken {
        val suite = params["suite"]
            ?: throw UriFormatException("У QR-коді відсутній OCRA-профіль (suite)")
        return ParsedQr.OcraToken(
            issuer = params["issuer"]?.ifBlank { null } ?: "Без назви",
            account = params["account"] ?: "",
            secret = requireSecret(params),
            suite = suite,
        )
    }

    private fun parseOcraChallenge(params: Map<String, String>): ParsedQr.OcraChallenge {
        val suite = params["suite"]
            ?: throw UriFormatException("У виклику відсутній OCRA-профіль (suite)")
        val q = params["q"]?.ifBlank { null }
            ?: throw UriFormatException("У виклику відсутнє значення Q")
        val cid = params["cid"]
            ?: throw UriFormatException("У виклику відсутній ідентифікатор (cid)")
        return ParsedQr.OcraChallenge(
            suite = suite,
            q = q, // формат виклику валідується ядром за профілем (QN/QA/QH)
            cid = cid,
            expSeconds = params["exp"]?.toIntOrNull() ?: 120,
            label = params["label"],
            counter = params["c"]?.toLongOrNull(),
            sessionB64 = params["s"],
            mode = params["mode"],
        )
    }

    private fun parseOcraMutual(params: Map<String, String>): ParsedQr.OcraMutualChallenge {
        fun required(key: String, what: String): String = params[key]?.ifBlank { null }
            ?: throw UriFormatException("У виклику взаємної автентифікації відсутній $what ($key)")
        return ParsedQr.OcraMutualChallenge(
            clientSuite = required("csuite", "профіль клієнта"),
            serverSuite = required("ssuite", "профіль сервера"),
            qc = required("qc", "виклик клієнта"),
            qs = required("qs", "виклик сервера"),
            serverResponse = required("srv", "відгук сервера"),
            cid = required("cid", "ідентифікатор"),
            expSeconds = params["exp"]?.toIntOrNull() ?: 120,
            label = params["label"],
        )
    }

    // -- Спільні перевірки --------------------------------------------------

    private fun checkVersion(params: Map<String, String>) {
        val version = params["v"]
            ?: throw UriFormatException("У QR-коді відсутня версія формату (v)")
        if (version != SUPPORTED_VERSION) {
            throw UriFormatException("Версія формату $version не підтримується. Оновіть додаток.")
        }
    }

    private fun requireSecret(params: Map<String, String>): ByteArray {
        val raw = params["secret"]
            ?: throw UriFormatException("У QR-коді відсутній секрет")
        val secret = try {
            Base32.decode(raw)
        } catch (e: IllegalArgumentException) {
            throw UriFormatException("Секрет не є коректним Base32: ${e.message}")
        }
        if (secret.size < 10) {
            throw UriFormatException("Секрет закороткий: потрібно щонайменше 10 байтів")
        }
        if (secret.size > 64) {
            throw UriFormatException("Секрет задовгий: максимум 64 байти")
        }
        return secret
    }

    private fun requireDigits(params: Map<String, String>, max: Int): Int {
        val digits = params["digits"]?.toIntOrNull() ?: 6
        if (digits !in 6..max) {
            throw UriFormatException("Довжина коду $digits поза допустимими межами 6–$max")
        }
        return digits
    }

    private fun requirePeriod(params: Map<String, String>): Int {
        val period = params["period"]?.toIntOrNull() ?: 30
        if (period !in 15..120) {
            throw UriFormatException("Період $period с поза допустимими межами 15–120 с")
        }
        return period
    }

    private fun splitLabel(label: String): Pair<String, String> {
        val parts = label.split(":", limit = 2)
        return if (parts.size == 2) parts[0].trim() to parts[1].trim() else "" to label.trim()
    }

    private fun parseQuery(query: String): Map<String, String> =
        query.split("&")
            .filter { it.isNotBlank() }
            .associate { pair ->
                val idx = pair.indexOf('=')
                if (idx < 0) decode(pair) to ""
                else decode(pair.take(idx)) to decode(pair.substring(idx + 1))
            }

    private fun decode(s: String): String = try {
        URLDecoder.decode(s, Charsets.UTF_8)
    } catch (e: IllegalArgumentException) {
        throw UriFormatException("QR-код містить пошкоджені символи")
    }
    private fun encode(s: String): String = URLEncoder.encode(s, Charsets.UTF_8).replace("+", "%20")
}
