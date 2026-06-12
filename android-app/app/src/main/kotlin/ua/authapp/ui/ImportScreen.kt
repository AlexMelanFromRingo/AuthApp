package ua.authapp.ui

import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.migration.FrameCodec
import ua.authapp.crypto.migration.MigrationCrypto
import ua.authapp.crypto.migration.MigrationOpenException
import ua.authapp.migration.parseManifest
import ua.authapp.migration.qrBitmap
import ua.authapp.scanner.QrScanner

/**
 * Імпорт пакета (US4; FR-017, FR-018): сканування кадрів із прогресом і
 * дозбиранням → парольна фраза → атомарний імпорт → QR-квитанція.
 *
 * УВАГА (урок першого польового прогону): ВЕСЬ прогрес тримаємо у
 * snapshot-станах Compose. FrameAssembler — звичайний об'єкт, його полів
 * композиція «не бачить»: початково жоден стан не читався, тож оновлення
 * не викликали рекомпозиції — екран замерзав на камері попри прийняті кадри.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore
    val assembler = remember { FrameCodec.FrameAssembler() }

    // Дзеркало стану assembler у snapshot-станах — єдине джерело для UI
    var receivedCount by remember { mutableIntStateOf(0) }
    var totalFrames by remember { mutableStateOf<Int?>(null) }
    var missingFrames by remember { mutableStateOf<List<Int>>(emptyList()) }
    var allFramesReceived by remember { mutableStateOf(false) }

    var error by remember { mutableStateOf<String?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var receiptUri by remember { mutableStateOf<String?>(null) }
    var importedCount by remember { mutableIntStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.import_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        when {
            // Крок 3: квитанція для старого пристрою
            receiptUri != null -> Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(stringResource(R.string.receipt_title), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(R.string.import_success, importedCount))
                Image(
                    bitmap = remember { qrBitmap(receiptUri!!) }.asImageBitmap(),
                    contentDescription = null,
                    filterQuality = FilterQuality.None,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            // Крок 2: всі кадри зібрано — парольна фраза і розшифрування
            allFramesReceived -> Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    stringResource(R.string.import_progress, receivedCount, totalFrames ?: receivedCount),
                    style = MaterialTheme.typography.titleMedium,
                )
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.export_passphrase)) },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(
                    enabled = passphrase.isNotEmpty(),
                    onClick = {
                        error = null
                        try {
                            val pkg = assembler.assemble()
                            val manifest = MigrationCrypto.open(passphrase.toCharArray(), pkg)
                            val tokens = parseManifest(manifest)
                            // Атомарність: записуємо лише після успішного
                            // розбору всього маніфесту (FR-017)
                            tokens.forEach(store::save)
                            importedCount = tokens.size
                            receiptUri = FrameCodec.receiptUri(
                                pkg.pid,
                                MigrationCrypto.receiptMac(passphrase.toCharArray(), manifest, pkg),
                            )
                        } catch (e: MigrationOpenException) {
                            error = context.getString(R.string.import_wrong_passphrase)
                        } catch (e: UriFormatException) {
                            error = e.message
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.action_next)) }
            }

            // Крок 1: сканування кадрів із прогресом
            else -> Column(modifier = Modifier.fillMaxSize().padding(padding)) {
                // Блок прогресу читає стани БЕЗУМОВНО — підписка з першої композиції
                val total = totalFrames
                LinearProgressIndicator(
                    progress = {
                        if (total == null || total == 0) 0f
                        else receivedCount.toFloat() / total
                    },
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                )
                Text(
                    text = if (total == null) {
                        stringResource(R.string.import_scan_first_frame)
                    } else {
                        stringResource(R.string.import_progress, receivedCount, total) +
                            missingFrames.takeIf { it.isNotEmpty() }
                                ?.let { " • " + stringResource(R.string.import_missing_frames, it.joinToString()) }
                                .orEmpty()
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp))
                }
                QrScanner(
                    onResult = { raw ->
                        try {
                            error = null
                            if (assembler.accept(raw)) {
                                // Синхронізуємо ВСІ стани з assembler
                                receivedCount = assembler.receivedCount
                                totalFrames = assembler.total
                                missingFrames = assembler.missingFrames()
                                allFramesReceived = assembler.isComplete
                                Toast.makeText(
                                    context,
                                    context.getString(
                                        R.string.import_progress,
                                        receivedCount,
                                        assembler.total ?: receivedCount,
                                    ),
                                    Toast.LENGTH_SHORT,
                                ).show()
                            }
                        } catch (e: UriFormatException) {
                            error = e.message
                            Toast.makeText(context, e.message, Toast.LENGTH_LONG).show()
                        }
                    },
                )
            }
        }
    }
}
