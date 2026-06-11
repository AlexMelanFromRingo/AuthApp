package ua.authapp.ui

import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import ua.authapp.AuthApplication
import ua.authapp.R
import ua.authapp.crypto.codec.GoogleAuthMigration
import ua.authapp.crypto.codec.OtpUri
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.mac.HashAlgorithm
import ua.authapp.scanner.QrScanner
import ua.authapp.storage.Token

/**
 * Додавання токена (US1; FR-005/006/025/026):
 * — вкладка «Сканер QR»: власні QR, otpauth://, а також експорт
 *   Google Authenticator (otpauth-migration://, кілька токенів за раз);
 * — вкладка «Вручну»: введення секрету рядком, як «ключ налаштування» в GA.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddTokenScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore
    val snackbar = remember { SnackbarHostState() }

    var tab by remember { mutableIntStateOf(0) }
    var scanError by remember { mutableStateOf<String?>(null) }
    var duplicateCandidate by remember { mutableStateOf<Pair<Token, Token>?>(null) }

    scanError?.let { message ->
        LaunchedEffect(message) {
            snackbar.showSnackbar(message)
            scanError = null
        }
    }

    fun handleNewToken(token: Token) {
        val existing = store.findDuplicate(token)
        if (existing != null) {
            duplicateCandidate = existing to token
        } else {
            store.save(token)
            confirmAdded(context, token.issuer)
            onDone()
        }
    }

    fun handleMigrationImport(raw: String) {
        val result = GoogleAuthMigration.parse(raw)
        var imported = 0
        result.tokens.forEach { parsed ->
            val token = Token.fromParsed(parsed)
            // При масовому імпорті дублікати тихо пропускаємо
            if (store.findDuplicate(token) == null) {
                store.save(token)
                imported++
            }
        }
        val summary = if (result.skipped > 0) {
            context.getString(R.string.gauth_imported_skipped, imported, result.skipped)
        } else {
            context.getString(R.string.gauth_imported, imported)
        }
        Toast.makeText(context, summary, Toast.LENGTH_LONG).show()
        if (result.batchSize > 1 && result.batchIndex < result.batchSize - 1) {
            // Багаточастинний експорт: лишаємося на сканері для решти QR
            scanError = context.getString(
                R.string.gauth_batch_hint, result.batchIndex + 1, result.batchSize,
            )
        } else {
            onDone()
        }
    }

    duplicateCandidate?.let { (existing, candidate) ->
        AlertDialog(
            onDismissRequest = { duplicateCandidate = null },
            title = { Text(stringResource(R.string.add_duplicate_title)) },
            text = { Text(stringResource(R.string.add_duplicate_message)) },
            confirmButton = {
                TextButton(onClick = {
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
        topBar = { TopAppBar(title = { Text(stringResource(R.string.token_add)) }) },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 },
                    text = { Text(stringResource(R.string.add_tab_scan)) })
                Tab(selected = tab == 1, onClick = { tab = 1 },
                    text = { Text(stringResource(R.string.add_tab_manual)) })
            }
            when (tab) {
                0 -> QrScanner(
                    onResult = { raw ->
                        try {
                            if (GoogleAuthMigration.isMigrationUri(raw)) {
                                handleMigrationImport(raw)
                            } else {
                                handleNewToken(Token.fromParsed(OtpUri.parse(raw)))
                            }
                        } catch (e: UriFormatException) {
                            scanError = e.message
                        } catch (e: IllegalArgumentException) {
                            scanError = e.message ?: context.getString(R.string.scan_invalid_qr)
                        }
                    },
                )
                1 -> ManualEntryForm(
                    onError = { scanError = it },
                    onToken = ::handleNewToken,
                )
            }
        }
    }
}

@Composable
private fun ManualEntryForm(
    onError: (String) -> Unit,
    onToken: (Token) -> Unit,
) {
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var algorithm by remember { mutableStateOf(HashAlgorithm.SHA1) }
    var digits by remember { mutableIntStateOf(6) }
    var period by remember { mutableIntStateOf(30) }

    val maxDigits = if (algorithm.isExtended) 10 else 8
    if (digits > maxDigits) digits = maxDigits

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        OutlinedTextField(
            value = issuer, onValueChange = { issuer = it },
            label = { Text(stringResource(R.string.manual_issuer)) },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = account, onValueChange = { account = it },
            label = { Text(stringResource(R.string.manual_account)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        OutlinedTextField(
            value = secret, onValueChange = { secret = it },
            label = { Text(stringResource(R.string.manual_secret)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        Row(Modifier.fillMaxWidth().padding(top = 8.dp)) {
            DropdownField(
                label = stringResource(R.string.manual_algorithm),
                value = algorithm.id,
                options = HashAlgorithm.entries.map { it.id },
                onSelect = { algorithm = HashAlgorithm.fromId(it)!! },
                modifier = Modifier.weight(1.4f).padding(end = 8.dp),
            )
            DropdownField(
                label = stringResource(R.string.manual_digits),
                value = digits.toString(),
                options = (6..maxDigits).map { it.toString() },
                onSelect = { digits = it.toInt() },
                modifier = Modifier.weight(0.8f).padding(end = 8.dp),
            )
            DropdownField(
                label = stringResource(R.string.manual_period),
                value = period.toString(),
                options = listOf("15", "30", "60", "120"),
                onSelect = { period = it.toInt() },
                modifier = Modifier.weight(0.8f),
            )
        }
        Button(
            enabled = secret.isNotBlank(),
            onClick = {
                try {
                    val parsed = OtpUri.manualTotp(issuer, account, secret, algorithm, digits, period)
                    onToken(Token.fromParsed(parsed))
                } catch (e: UriFormatException) {
                    onError(e.message.orEmpty())
                }
            },
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
        ) { Text(stringResource(R.string.manual_save)) }
    }
}

/** Простий випадний список: підпис + кнопка зі значенням. */
@Composable
private fun DropdownField(
    label: String,
    value: String,
    options: List<String>,
    onSelect: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    Column(modifier) {
        Text(label, style = androidx.compose.material3.MaterialTheme.typography.labelMedium)
        Box {
            OutlinedButton(onClick = { expanded = true }, modifier = Modifier.fillMaxWidth()) {
                Text(value, maxLines = 1)
            }
            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                options.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(option) },
                        onClick = {
                            onSelect(option)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

private fun confirmAdded(context: Context, issuer: String) {
    Toast.makeText(context, context.getString(R.string.add_success, issuer), Toast.LENGTH_SHORT).show()
}
