package ua.authapp.ui

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import ua.authapp.AuthApplication
import ua.authapp.R
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.migration.ExportSession
import ua.authapp.scanner.QrScanner

/**
 * Хаб перенесення (US4): експорт, імпорт, сканування квитанції та
 * деактивація (FR-018, FR-019). Штатна деактивація доступна лише після
 * верифікованої квитанції; примусова — через подвійне підтвердження.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MigrationScreen(
    onExport: () -> Unit,
    onImport: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore

    var scanningReceipt by remember { mutableStateOf(false) }
    var receiptVerified by remember { mutableStateOf(false) }
    var receiptError by remember { mutableStateOf<String?>(null) }

    // Кроки підтвердження деактивації: 0 — немає, 1 — перше, 2 — друге (примусова)
    var deactivateStep by remember { mutableStateOf(0) }
    var forced by remember { mutableStateOf(false) }

    fun performErase() {
        store.cryptoErase()
        ExportSession.clear()
        Toast.makeText(context, context.getString(R.string.deactivate_done), Toast.LENGTH_LONG).show()
        deactivateStep = 0
        receiptVerified = false
    }

    if (scanningReceipt) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(stringResource(R.string.receipt_scan)) },
                    navigationIcon = {
                        IconButton(onClick = { scanningReceipt = false }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                        }
                    },
                )
            },
        ) { padding ->
            Column(Modifier.fillMaxSize().padding(padding)) {
                QrScanner(
                    onResult = { raw ->
                        scanningReceipt = false
                        try {
                            if (ExportSession.verifyReceipt(raw)) {
                                receiptVerified = true
                                receiptError = null
                            } else {
                                receiptError = context.getString(R.string.receipt_invalid)
                            }
                        } catch (e: UriFormatException) {
                            receiptError = e.message
                        }
                    },
                )
            }
        }
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.migration_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(onClick = onExport, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.export_title))
            }
            Button(onClick = onImport, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.import_title))
            }
            OutlinedButton(
                onClick = { scanningReceipt = true },
                enabled = ExportSession.sealedPackage != null,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.receipt_scan))
            }

            receiptError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (receiptVerified) {
                Text(
                    stringResource(R.string.receipt_verified),
                    color = MaterialTheme.colorScheme.primary,
                )
            }

            OutlinedButton(
                onClick = {
                    forced = !receiptVerified
                    deactivateStep = 1
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    stringResource(R.string.deactivate_title),
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }

    // Перше підтвердження — завжди; друге — лише для примусової деактивації
    if (deactivateStep >= 1) {
        AlertDialog(
            onDismissRequest = { deactivateStep = 0 },
            title = { Text(stringResource(R.string.deactivate_title)) },
            text = {
                Text(
                    stringResource(
                        if (deactivateStep == 2 || (deactivateStep == 1 && !forced)) {
                            R.string.deactivate_warning
                        } else {
                            R.string.deactivate_force_warning
                        },
                    ),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    when {
                        // Штатна (квитанція верифікована): одне підтвердження
                        !forced -> performErase()
                        // Примусова: два явні підтвердження (FR-019)
                        deactivateStep == 1 -> deactivateStep = 2
                        else -> performErase()
                    }
                }) { Text(stringResource(R.string.deactivate_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { deactivateStep = 0 }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}
