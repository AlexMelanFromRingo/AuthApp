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
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore
    val assembler = remember { FrameCodec.FrameAssembler() }

    var receivedCount by remember { mutableIntStateOf(0) }
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
            assembler.isComplete -> Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
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
                val total = assembler.total
                if (total != null) {
                    LinearProgressIndicator(
                        progress = { receivedCount.toFloat() / total },
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                    )
                    Text(
                        text = stringResource(R.string.import_progress, receivedCount, total) +
                            assembler.missingFrames().takeIf { it.isNotEmpty() }
                                ?.let { " • " + stringResource(R.string.import_missing_frames, it.joinToString()) }
                                .orEmpty(),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(horizontal = 16.dp),
                    )
                }
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp))
                }
                QrScanner(
                    onResult = { raw ->
                        try {
                            error = null
                            if (assembler.accept(raw)) {
                                receivedCount = assembler.receivedCount
                                // Гучне підтвердження кожного кадра — прогрес
                                // угорі легко не помітити, тримаючи два пристрої
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
