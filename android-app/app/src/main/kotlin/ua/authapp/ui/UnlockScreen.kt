package ua.authapp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import ua.authapp.R
import ua.authapp.biometric.BiometricGate
import ua.authapp.biometric.BiometricState

/**
 * Екран розблокування: єдиний шлях до токенів — успішний BiometricPrompt.
 * Стани недоступності біометрії пояснюються користувачеві (edge cases spec.md).
 */
@Composable
fun UnlockScreen(onUnlocked: () -> Unit) {
    val activity = LocalContext.current as FragmentActivity
    val gate = remember { BiometricGate(activity) }
    var message by remember { mutableStateOf<String?>(null) }
    val state = remember { gate.state() }

    // Показуємо запит одразу при появі екрана
    LaunchedEffect(Unit) {
        if (state == BiometricState.AVAILABLE) {
            gate.prompt(onSuccess = onUnlocked, onFailure = { message = it?.toString() })
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Filled.Lock, contentDescription = null)
        Spacer(Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.unlock_title),
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = when (state) {
                BiometricState.NO_HARDWARE -> stringResource(R.string.unlock_error_no_hardware)
                BiometricState.NOT_ENROLLED -> stringResource(R.string.unlock_error_not_enrolled)
                BiometricState.UNAVAILABLE -> stringResource(R.string.unlock_error_unavailable)
                BiometricState.AVAILABLE -> message ?: stringResource(R.string.unlock_subtitle)
            },
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        if (state == BiometricState.AVAILABLE) {
            Button(onClick = {
                message = null
                gate.prompt(onSuccess = onUnlocked, onFailure = { message = it?.toString() })
            }) {
                Text(stringResource(R.string.unlock_button))
            }
        }
    }
}
