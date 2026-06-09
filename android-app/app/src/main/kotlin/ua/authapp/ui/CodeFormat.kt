package ua.authapp.ui

/**
 * Групування цифр коду для читабельності: рівні групи без «хвостів».
 * 6 → 3+3, 8 → 4+4, 9 → 3+3+3, 10 → 5+5, 7 → 3+4.
 */
fun groupCode(code: String): String = when {
    code.length % 3 == 0 -> code.chunked(3)
    code.length % 4 == 0 -> code.chunked(4)
    code.length % 5 == 0 -> code.chunked(5)
    else -> listOf(code.take(3), code.drop(3))
}.joinToString(" ")
