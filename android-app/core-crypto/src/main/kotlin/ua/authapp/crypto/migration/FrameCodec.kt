package ua.authapp.crypto.migration

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import ua.authapp.crypto.codec.UriFormatException

/**
 * Кадрування пакета міграції в серію QR (contracts/qr-uri-schemes.md §4–5, R6):
 *
 * `authapp://migrate?v=1&pid=...&i=<1..n>&n=<всього>&data=<base64url ≤512Б>`
 *
 * Кадр 1 — заголовок (JSON: версія, сіль, параметри KDF, nonce, довжина
 * шифротексту), кадри 2..n — фрагменти шифротексту. Кадри приймаються в
 * довільному порядку; бітова карта дозволяє дозбирати пропущені (FR-017).
 */
object FrameCodec {

    // 256 Б на кадр → QR ~версії 15 (77×77 модулів): впевнено сканується
    // екран-у-камеру; 512 Б давали ~версію 22, заважку для сканера
    const val CHUNK_SIZE = 256

    @Serializable
    data class Header(
        val version: Int,
        val saltB64: String,
        val m: Int, val t: Int, val p: Int,
        val nonceB64: String,
        val ctLen: Int,
    )

    private val json = Json { ignoreUnknownKeys = true }

    // -- Експорт --------------------------------------------------------------

    fun toFrames(pkg: SealedPackage): List<String> {
        val header = Header(
            version = pkg.version,
            saltB64 = Base64Url.encode(pkg.salt),
            m = pkg.kdfParams.memoryKib,
            t = pkg.kdfParams.iterations,
            p = pkg.kdfParams.parallelism,
            nonceB64 = Base64Url.encode(pkg.nonce),
            ctLen = pkg.ciphertext.size,
        )
        val chunks = pkg.ciphertext.toList().chunked(CHUNK_SIZE).map { it.toByteArray() }
        val total = 1 + chunks.size
        val frames = ArrayList<String>(total)
        frames += frameUri(pkg.pid, 1, total, json.encodeToString(Header.serializer(), header).toByteArray())
        chunks.forEachIndexed { index, chunk ->
            frames += frameUri(pkg.pid, index + 2, total, chunk)
        }
        return frames
    }

    private fun frameUri(pid: String, i: Int, n: Int, data: ByteArray): String =
        "authapp://migrate?v=1&pid=$pid&i=$i&n=$n&data=${Base64Url.encode(data)}"

    // -- Квитанція ------------------------------------------------------------

    fun receiptUri(pid: String, mac: ByteArray): String =
        "authapp://migrate-receipt?v=1&pid=$pid&mac=${Base64Url.encode(mac)}"

    data class Receipt(val pid: String, val mac: ByteArray)

    fun parseReceiptUri(raw: String): Receipt {
        val params = parseUri(raw, expectedHost = "migrate-receipt")
        return Receipt(
            pid = params["pid"] ?: throw UriFormatException("У квитанції відсутній pid"),
            mac = decode(params, "mac"),
        )
    }

    // -- Імпорт: збирання кадрів у довільному порядку --------------------------

    class FrameAssembler {
        var pid: String? = null
            private set
        var total: Int? = null
            private set
        private val received = sortedMapOf<Int, ByteArray>()

        val receivedCount: Int get() = received.size

        /** Номери відсутніх кадрів — для повідомлення «кадр X із N відсутній». */
        fun missingFrames(): List<Int> {
            val n = total ?: return emptyList()
            return (1..n).filter { it !in received }
        }

        val isComplete: Boolean get() = total?.let { received.size == it } == true

        /**
         * Приймає один кадр; повторні та чужі кадри ігноруються безпечно.
         * @return true, якщо кадр було прийнято (новий і від цього ж пакета)
         */
        fun accept(raw: String): Boolean {
            val params = parseUri(raw, expectedHost = "migrate")
            val framePid = params["pid"] ?: throw UriFormatException("У кадрі відсутній pid")
            val i = params["i"]?.toIntOrNull() ?: throw UriFormatException("У кадрі відсутній номер (i)")
            val n = params["n"]?.toIntOrNull() ?: throw UriFormatException("У кадрі відсутня кількість (n)")
            if (i !in 1..n) throw UriFormatException("Некоректний номер кадру: $i із $n")

            if (pid == null) {
                pid = framePid
                total = n
            } else if (pid != framePid) {
                return false // кадр іншого експорту — ігноруємо
            }
            if (i in received) return false
            received[i] = decode(params, "data")
            return true
        }

        /** Складає пакет після отримання всіх кадрів. */
        fun assemble(): SealedPackage {
            check(isComplete) { "Отримано не всі кадри: відсутні ${missingFrames()}" }
            val header = json.decodeFromString(
                Header.serializer(),
                received.getValue(1).toString(Charsets.UTF_8),
            )
            if (header.version != MigrationCrypto.FORMAT_VERSION) {
                throw UriFormatException("Версія пакета ${header.version} не підтримується. Оновіть додаток.")
            }
            val ciphertext = ByteArray(header.ctLen)
            var pos = 0
            for (i in 2..(total ?: 0)) {
                val chunk = received.getValue(i)
                chunk.copyInto(ciphertext, pos)
                pos += chunk.size
            }
            if (pos != header.ctLen) {
                throw UriFormatException("Пакет пошкоджено: довжина даних не збігається із заголовком")
            }
            return SealedPackage(
                pid = requireNotNull(pid),
                version = header.version,
                salt = Base64Url.decode(header.saltB64),
                kdfParams = KdfParams(header.m, header.t, header.p),
                nonce = Base64Url.decode(header.nonceB64),
                ciphertext = ciphertext,
            )
        }
    }

    // -- Допоміжне -------------------------------------------------------------

    private fun parseUri(raw: String, expectedHost: String): Map<String, String> {
        val match = Regex("^authapp://([a-z-]+)\\?(.*)$").matchEntire(raw.trim())
            ?: throw UriFormatException("QR-код не є кадром міграції")
        if (match.groupValues[1] != expectedHost) {
            throw UriFormatException("Очікувався QR типу «$expectedHost», отримано «${match.groupValues[1]}»")
        }
        val params = match.groupValues[2].split("&").filter { it.isNotBlank() }.associate {
            val idx = it.indexOf('=')
            if (idx < 0) it to "" else it.take(idx) to it.substring(idx + 1)
        }
        if (params["v"] != "1") {
            throw UriFormatException("Версія формату ${params["v"]} не підтримується. Оновіть додаток.")
        }
        return params
    }

    private fun decode(params: Map<String, String>, key: String): ByteArray = try {
        Base64Url.decode(params[key] ?: throw UriFormatException("Відсутній параметр $key"))
    } catch (e: IllegalArgumentException) {
        throw UriFormatException("Пошкоджені дані у параметрі $key")
    }
}
