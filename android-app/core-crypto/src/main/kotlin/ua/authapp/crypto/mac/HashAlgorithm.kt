package ua.authapp.crypto.mac

/**
 * Спільний словник алгоритмів (data-model.md): канонічні ідентифікатори
 * однакові в Kotlin, JS, URI та тестових векторах.
 */
enum class HashAlgorithm(
    /** Канонічний ідентифікатор у URI та векторах */
    val id: String,
    /** Довжина MAC у байтах */
    val macLength: Int,
    /** Розширений алгоритм використовує узагальнене усічення (FR-009) */
    val isExtended: Boolean,
) {
    SHA1("SHA1", 20, false),
    SHA256("SHA256", 32, false),
    SHA512("SHA512", 64, false),
    SHA3_256("SHA3-256", 32, true),
    BLAKE2S_256("BLAKE2S-256", 32, true),
    BLAKE2B_512("BLAKE2B-512", 64, true),
    BLAKE3_256("BLAKE3-256", 32, true);

    companion object {
        /** Пошук за канонічним ідентифікатором (незалежно від регістру). */
        fun fromId(id: String): HashAlgorithm? =
            entries.firstOrNull { it.id.equals(id, ignoreCase = true) }
    }
}
