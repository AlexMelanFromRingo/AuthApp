package ua.authapp

import android.app.Application
import ua.authapp.storage.TokenStore

/** Точка входу процесу: єдиний екземпляр сховища токенів. */
class AuthApplication : Application() {

    lateinit var tokenStore: TokenStore
        private set

    override fun onCreate() {
        super.onCreate()
        tokenStore = TokenStore(this)
    }
}
