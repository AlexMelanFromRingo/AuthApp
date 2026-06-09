package ua.authapp.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ua.authapp.crypto.totp.Totp
import ua.authapp.storage.Token
import ua.authapp.storage.TokenStore
import ua.authapp.storage.TokenType

/** Поточний стан одного рядка списку. */
data class TokenRow(
    val token: Token,
    /** Згенерований код (для OCRA-токенів — null: вони працюють на екрані OCRA) */
    val code: String?,
    /** Секунд до зміни коду */
    val secondsLeft: Int,
)

/**
 * Генерація кодів поза головним потоком із тіком раз на секунду (FR-010/011).
 * Секрети і згенеровані коди НІКОЛИ не пишуться в логи (FR-003).
 */
class TokenListViewModel(private val store: TokenStore) : ViewModel() {

    private val _rows = MutableStateFlow<List<TokenRow>>(emptyList())
    val rows: StateFlow<List<TokenRow>> = _rows.asStateFlow()

    init {
        viewModelScope.launch {
            while (isActive) {
                refresh()
                // Прокидаємося на межі секунди, щоб індикатор не «стрибав»
                delay(1000L - System.currentTimeMillis() % 1000L)
            }
        }
    }

    fun refresh() {
        viewModelScope.launch {
            _rows.value = withContext(Dispatchers.Default) {
                val now = System.currentTimeMillis() / 1000
                store.list().map { token ->
                    when (token.type) {
                        TokenType.TOTP -> TokenRow(
                            token = token,
                            code = Totp.generate(
                                token.algorithm, token.secret, now, token.period, token.digits,
                            ),
                            secondsLeft = (token.period - (now % token.period)).toInt(),
                        )
                        TokenType.OCRA -> TokenRow(token, code = null, secondsLeft = 0)
                    }
                }
            }
        }
    }

    fun rename(token: Token, newIssuer: String) {
        store.save(token.copy(issuer = newIssuer))
        refresh()
    }

    fun delete(token: Token) {
        store.delete(token.id)
        refresh()
    }
}
