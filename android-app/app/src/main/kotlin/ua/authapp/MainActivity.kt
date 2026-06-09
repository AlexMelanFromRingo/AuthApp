package ua.authapp

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import ua.authapp.ui.AppNav
import ua.authapp.ui.theme.AuthAppTheme

/**
 * Єдина активність додатка. FragmentActivity потрібна для BiometricPrompt.
 * FLAG_SECURE забороняє скріншоти і запис екрана на всіх екранах із секретами
 * (Конституція, Принцип I; FR-003).
 */
class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContent {
            AuthAppTheme {
                AppNav()
            }
        }
    }
}
