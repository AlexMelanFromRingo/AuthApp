package ua.authapp.crypto.codec

/**
 * Base32 за RFC 4648 (алфавіт A–Z, 2–7) без паддінгу — формат секретів
 * у otpauth-сумісних URI. Декодер толерантний до регістру, пробілів і '='.
 */
object Base32 {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val DECODE_MAP = IntArray(128) { -1 }.also { map ->
        ALPHABET.forEachIndexed { index, c ->
            map[c.code] = index
            map[c.lowercaseChar().code] = index
        }
    }

    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val result = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0L
        var bits = 0
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toLong() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                result.append(ALPHABET[((buffer shr bits) and 0x1F).toInt()])
            }
        }
        if (bits > 0) {
            result.append(ALPHABET[((buffer shl (5 - bits)) and 0x1F).toInt()])
        }
        return result.toString()
    }

    fun decode(text: String): ByteArray {
        val clean = text.filter { it != ' ' && it != '=' && it != '-' }
        if (clean.isEmpty()) return ByteArray(0)
        val out = ArrayList<Byte>(clean.length * 5 / 8)
        var buffer = 0L
        var bits = 0
        for (c in clean) {
            val value = if (c.code < 128) DECODE_MAP[c.code] else -1
            require(value >= 0) { "Недопустимий символ Base32: «$c»" }
            buffer = (buffer shl 5) or value.toLong()
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.add(((buffer shr bits) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }
}
