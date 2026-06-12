package ua.authapp.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import ua.authapp.AuthApplication
import ua.authapp.R
import ua.authapp.migration.ExportSession
import ua.authapp.migration.qrBitmap

/**
 * Експорт токенів (US4; FR-016): вибір токенів → парольна фраза (двічі) →
 * послідовний показ QR-кадрів. Після показу останнього кадру користувач
 * сканує квитанцію з нового пристрою на екрані «Перенесення».
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore
    val tokens = remember { store.list() }

    var selected by remember { mutableStateOf(tokens.map { it.id }.toSet()) }
    var passphrase by remember { mutableStateOf("") }
    var passphraseRepeat by remember { mutableStateOf("") }
    var frames by remember { mutableStateOf<List<String>>(emptyList()) }
    var frameIndex by remember { mutableStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.export_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        if (frames.isEmpty()) {
            // Крок 1: вибір токенів і парольна фраза
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(stringResource(R.string.export_select_tokens), style = MaterialTheme.typography.titleMedium)
                tokens.forEach { token ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = token.id in selected,
                            onCheckedChange = { checked ->
                                selected = if (checked) selected + token.id else selected - token.id
                            },
                        )
                        Text("${token.issuer} (${token.account})")
                    }
                }
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.export_passphrase)) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = passphraseRepeat,
                    onValueChange = { passphraseRepeat = it },
                    label = { Text(stringResource(R.string.export_passphrase_repeat)) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(
                    enabled = selected.isNotEmpty() && passphrase.length >= 8,
                    onClick = {
                        if (passphrase != passphraseRepeat) {
                            error = context.getString(R.string.export_passphrase_mismatch)
                            return@Button
                        }
                        error = null
                        // Argon2id (64 МіБ) працює ~секунду — для дипломного
                        // обсягу прийнятно виконати синхронно з індикатором
                        frames = ExportSession.start(
                            tokens.filter { it.id in selected },
                            passphrase.toCharArray(),
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.action_next)) }
            }
        } else {
            // Крок 2: ручний показ QR-кадрів — після підтвердження на
            // імпортері («Отримано кадрів: X із N») тисніть «Далі».
            // Автопрокрутку прибрано за результатами польового прогону:
            // карусель збивала з пантелику і заважала навестися на кадр.
            val bitmap = remember(frameIndex) { qrBitmap(frames[frameIndex]) }
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    stringResource(R.string.export_frame_counter, frameIndex + 1, frames.size),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    stringResource(R.string.export_frame_hint),
                    style = MaterialTheme.typography.bodySmall,
                )
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = null,
                    // Без згладжування: краї модулів QR лишаються різкими
                    filterQuality = FilterQuality.None,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    TextButton(
                        enabled = frameIndex > 0,
                        onClick = { frameIndex-- },
                    ) { Text(stringResource(R.string.action_back)) }
                    Button(
                        enabled = frameIndex < frames.size - 1,
                        onClick = { frameIndex++ },
                    ) { Text(stringResource(R.string.action_next)) }
                }
                if (frameIndex == frames.size - 1) {
                    Text(
                        stringResource(R.string.receipt_title) + ": " +
                            stringResource(R.string.import_success, selected.size)
                                .substringAfter('.').trim(),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}
