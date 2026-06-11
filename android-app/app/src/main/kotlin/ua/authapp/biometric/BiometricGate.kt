package ua.authapp.biometric

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import ua.authapp.R

/** Стан бар'єра автентифікації додатка. */
enum class BiometricState {
    /** Доступна біометрія класу STRONG — основний шлях */
    BIOMETRIC,

    /**
     * Біометрії немає (сенсор відсутній або не налаштований), але є
     * системний PIN/ключ/пароль — резервний шлях (FR-028)
     */
    DEVICE_CREDENTIAL,

    /** Жодного захисту на пристрої — додаток недоступний */
    NO_PROTECTION,

    /** Тимчасово недоступно (сенсор зайнятий, оновлення безпеки тощо) */
    UNAVAILABLE,
}

/**
 * Бар'єр входу (FR-002, FR-028; Конституція Принцип I): доступ до токенів
 * СУВОРО через BiometricPrompt. Основний шлях — біометрія BIOMETRIC_STRONG;
 * якщо її немає — той самий BiometricPrompt із системним PIN/ключем
 * (DEVICE_CREDENTIAL): апаратний rate-limiting і захист Keyguard замість
 * власної реалізації PIN. Викликається при запуску і поверненні з фону.
 */
class BiometricGate(private val activity: FragmentActivity) {

    fun state(): BiometricState {
        val manager = BiometricManager.from(activity)
        when (manager.canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> return BiometricState.BIOMETRIC
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN,
            -> return BiometricState.UNAVAILABLE
            else -> Unit // немає сенсора чи реєстрації → пробуємо резервний шлях
        }
        return when (manager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricState.DEVICE_CREDENTIAL
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            -> BiometricState.NO_PROTECTION
            else -> BiometricState.UNAVAILABLE
        }
    }

    /**
     * Показує системний запит автентифікації відповідно до [state].
     * @param onSuccess доступ дозволено
     * @param onFailure термінальна помилка — додаток лишається заблокованим
     */
    fun prompt(onSuccess: () -> Unit, onFailure: (CharSequence?) -> Unit) {
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(activity.getString(R.string.unlock_title))
            .setSubtitle(activity.getString(R.string.unlock_subtitle))

        when (state()) {
            BiometricState.BIOMETRIC -> builder
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setNegativeButtonText(activity.getString(R.string.action_cancel))
            BiometricState.DEVICE_CREDENTIAL ->
                // З DEVICE_CREDENTIAL негативна кнопка заборонена API
                builder.setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            else -> {
                onFailure(null)
                return
            }
        }

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // Жодних деталей у логи: лише повідомлення користувачеві (FR-003)
                    onFailure(errString)
                }
            },
        )
        prompt.authenticate(builder.build())
    }
}
