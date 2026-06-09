package ua.authapp.biometric

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import ua.authapp.R

/** Стан біометричного бар'єра додатка. */
enum class BiometricState {
    /** Можна показувати запит */
    AVAILABLE,

    /** Сенсора немає взагалі — додаток недоступний */
    NO_HARDWARE,

    /** Сенсор є, але біометрію не налаштовано */
    NOT_ENROLLED,

    /** Тимчасово недоступна (зайнята, заблокована тощо) */
    UNAVAILABLE,
}

/**
 * Біометричний бар'єр (FR-002, Конституція Принцип I): доступ до токенів
 * СУВОРО після успішної перевірки класу BIOMETRIC_STRONG. Викликається при
 * запуску і щоразу при поверненні додатка з фону.
 */
class BiometricGate(private val activity: FragmentActivity) {

    fun state(): BiometricState =
        when (BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricState.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricState.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricState.NOT_ENROLLED
            else -> BiometricState.UNAVAILABLE
        }

    /**
     * Показує системний BiometricPrompt.
     * @param onSuccess доступ дозволено
     * @param onFailure термінальна помилка (скасування, блокування) — додаток
     *        лишається на екрані розблокування
     */
    fun prompt(onSuccess: () -> Unit, onFailure: (CharSequence?) -> Unit) {
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(activity.getString(R.string.unlock_title))
            .setSubtitle(activity.getString(R.string.unlock_subtitle))
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText(activity.getString(R.string.action_cancel))
            .build()

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
        prompt.authenticate(info)
    }
}
