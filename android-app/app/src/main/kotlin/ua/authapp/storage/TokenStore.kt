package ua.authapp.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.serialization.json.Json

/**
 * Захищене сховище токенів (FR-001, R4): EncryptedSharedPreferences,
 * майстер-ключ AES-256-GCM живе в Android Keystore і не покидає апаратного
 * сховища. Біометричний бар'єр діє на рівні застосунку (BiometricGate), а не
 * ключа — інакше зміна реєстрації біометрії безповоротно знищила б токени.
 *
 * Бібліотеку security-crypto переведено в режим супроводу (deprecated) —
 * прийнятий ризик за рішенням R4 research.md: API стабільний, явна вимога
 * замовника; міграція на DataStore + власний Keystore-шар — поза межами версії.
 */
@Suppress("DEPRECATION")
class TokenStore(context: Context) {

    private val json = Json { ignoreUnknownKeys = true }
    private val appContext = context.applicationContext

    private val masterKey = MasterKey.Builder(appContext, MASTER_KEY_ALIAS)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        appContext,
        PREFS_FILE,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun list(): List<Token> =
        prefs.all.keys
            .mapNotNull { key -> prefs.getString(key, null) }
            .map { json.decodeFromString<Token>(it) }
            .sortedBy { it.createdAt }

    fun get(id: String): Token? =
        prefs.getString(id, null)?.let { json.decodeFromString<Token>(it) }

    fun save(token: Token) {
        prefs.edit().putString(token.id, json.encodeToString(Token.serializer(), token)).apply()
    }

    fun delete(id: String) {
        prefs.edit().remove(id).apply()
    }

    /** Пошук збереженого дубліката для діалогу «замінити чи додати окремо». */
    fun findDuplicate(candidate: Token): Token? =
        list().firstOrNull { it.isDuplicateOf(candidate) }

    /**
     * Crypto-erase (FR-019): затирає всі записи і знищує майстер-ключ у
     * Keystore. Після цього залишковий шифротекст назавжди нерозшифровуваний,
     * токени не генерують кодів. ДІЯ НЕЗВОРОТНА.
     */
    fun cryptoErase() {
        prefs.edit().clear().commit()
        appContext.deleteSharedPreferences(PREFS_FILE)
        java.security.KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(MASTER_KEY_ALIAS)) deleteEntry(MASTER_KEY_ALIAS)
        }
    }

    private companion object {
        const val PREFS_FILE = "tokens"
        const val MASTER_KEY_ALIAS = "authapp_master_key"
    }
}
