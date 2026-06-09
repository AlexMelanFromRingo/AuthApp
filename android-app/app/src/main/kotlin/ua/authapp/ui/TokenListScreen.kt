package ua.authapp.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import ua.authapp.AuthApplication
import ua.authapp.R
import ua.authapp.storage.Token
import ua.authapp.storage.TokenType

/**
 * Головний екран (US1): живі TOTP-коди з індикатором залишку періоду,
 * копіювання по тапу з сповіщенням, перейменування/видалення з підтвердженням.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TokenListScreen(
    onAddToken: () -> Unit,
    onOpenOcra: () -> Unit,
    onOpenMigration: () -> Unit,
) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore
    val viewModel: TokenListViewModel = viewModel { TokenListViewModel(store) }
    val rows by viewModel.rows.collectAsState()

    var renameTarget by remember { mutableStateOf<Token?>(null) }
    var deleteTarget by remember { mutableStateOf<Token?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tokens_title)) },
                actions = {
                    TextButton(onClick = onOpenOcra) { Text("OCRA") }
                    TextButton(onClick = onOpenMigration) {
                        Text(stringResource(R.string.migration_title))
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAddToken) {
                Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.token_add))
            }
        },
    ) { padding ->
        if (rows.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding).padding(32.dp), contentAlignment = Alignment.Center) {
                Text(stringResource(R.string.tokens_empty), style = MaterialTheme.typography.bodyLarge)
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(rows, key = { it.token.id }) { row ->
                    TokenCard(
                        row = row,
                        onCopy = { code -> copyToClipboard(context, code) },
                        onRename = { renameTarget = row.token },
                        onDelete = { deleteTarget = row.token },
                    )
                }
            }
        }
    }

    renameTarget?.let { token ->
        RenameDialog(
            current = token.issuer,
            onConfirm = { viewModel.rename(token, it); renameTarget = null },
            onDismiss = { renameTarget = null },
        )
    }

    deleteTarget?.let { token ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.token_delete)) },
            text = { Text(stringResource(R.string.token_delete_confirm, token.issuer)) },
            confirmButton = {
                TextButton(onClick = { viewModel.delete(token); deleteTarget = null }) {
                    Text(stringResource(R.string.token_delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun TokenCard(
    row: TokenRow,
    onCopy: (String) -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = row.code != null) { row.code?.let(onCopy) },
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            // Шапка: назва + дії
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(row.token.issuer, style = MaterialTheme.typography.titleMedium)
                    if (row.token.account.isNotBlank()) {
                        Text(row.token.account, style = MaterialTheme.typography.bodySmall)
                    }
                }
                IconButton(onClick = onRename) {
                    Icon(Icons.Filled.Edit, contentDescription = stringResource(R.string.token_rename))
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.token_delete))
                }
            }
            when (row.token.type) {
                TokenType.TOTP -> {
                    // Код на всю ширину — навіть 10 цифр в один рядок
                    Text(
                        text = groupCode(row.code.orEmpty()),
                        style = MaterialTheme.typography.headlineMedium,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.primary,
                        maxLines = 1,
                    )
                    // Залишок періоду — окремим рядком знизу
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(top = 6.dp),
                    ) {
                        CircularProgressIndicator(
                            progress = { row.secondsLeft.toFloat() / row.token.period },
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.5.dp,
                        )
                        Text(
                            text = stringResource(R.string.token_seconds_left, row.secondsLeft),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                }
                TokenType.OCRA -> Text(
                    text = row.token.ocraSuite.orEmpty(),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun RenameDialog(current: String, onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var value by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.token_rename)) },
        text = {
            OutlinedTextField(value = value, onValueChange = { value = it }, singleLine = true)
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(value.trim()) }, enabled = value.isNotBlank()) {
                Text(stringResource(R.string.action_ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}

private fun copyToClipboard(context: Context, code: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    // Без «sensitive»-вмісту в описі; самого коду достатньо на ~30 секунд
    clipboard.setPrimaryClip(ClipData.newPlainText("", code.replace(" ", "")))
    Toast.makeText(context, context.getString(R.string.token_copied), Toast.LENGTH_SHORT).show()
}
