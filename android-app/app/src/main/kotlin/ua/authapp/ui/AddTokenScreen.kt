package ua.authapp.ui

import android.widget.Toast
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import ua.authapp.AuthApplication
import ua.authapp.R
import ua.authapp.crypto.codec.OtpUri
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.scanner.QrScanner
import ua.authapp.storage.Token

/**
 * Додавання токена: сканування QR → парсинг → валідація → діалог дубліката →
 * збереження (US1; FR-005, FR-006).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddTokenScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore
    val snackbar = remember { SnackbarHostState() }

    var scanError by remember { mutableStateOf<String?>(null) }
    var duplicateCandidate by remember { mutableStateOf<Pair<Token, Token>?>(null) }

    scanError?.let { message ->
        LaunchedEffect(message) {
            snackbar.showSnackbar(message)
            scanError = null
        }
    }

    duplicateCandidate?.let { (existing, candidate) ->
        AlertDialog(
            onDismissRequest = { duplicateCandidate = null },
            title = { Text(stringResource(R.string.add_duplicate_title)) },
            text = { Text(stringResource(R.string.add_duplicate_message)) },
            confirmButton = {
                TextButton(onClick = {
                    // Заміна: зберігаємо нові параметри під старим id
                    store.save(candidate.copy(id = existing.id))
                    duplicateCandidate = null
                    confirmAdded(context, candidate.issuer)
                    onDone()
                }) { Text(stringResource(R.string.add_duplicate_replace)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    store.save(candidate)
                    duplicateCandidate = null
                    confirmAdded(context, candidate.issuer)
                    onDone()
                }) { Text(stringResource(R.string.add_duplicate_keep_both)) }
            },
        )
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.scan_title)) }) },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        QrScanner(
            onResult = { raw ->
                try {
                    val token = Token.fromParsed(OtpUri.parse(raw))
                    val existing = store.findDuplicate(token)
                    if (existing != null) {
                        duplicateCandidate = existing to token
                    } else {
                        store.save(token)
                        confirmAdded(context, token.issuer)
                        onDone()
                    }
                } catch (e: UriFormatException) {
                    scanError = e.message
                } catch (e: IllegalArgumentException) {
                    scanError = e.message ?: context.getString(R.string.scan_invalid_qr)
                }
            },
        )
        Modifier.padding(padding)
    }
}

private fun confirmAdded(context: android.content.Context, issuer: String) {
    Toast.makeText(context, context.getString(R.string.add_success, issuer), Toast.LENGTH_SHORT).show()
}
