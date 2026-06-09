package ua.authapp.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import ua.authapp.AuthApplication
import ua.authapp.R
import ua.authapp.crypto.codec.OtpUri
import ua.authapp.crypto.codec.ParsedQr
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.ocra.Ocra
import ua.authapp.crypto.ocra.OcraSuite
import ua.authapp.scanner.QrScanner
import ua.authapp.storage.Token
import ua.authapp.storage.TokenType

/**
 * Окремий екран OCRA (US3; FR-012): сканування QR-виклику → пошук відповідного
 * токена (вибір за неоднозначності) → показ відгуку з копіюванням по тапу.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OcraScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore
    val snackbar = remember { SnackbarHostState() }

    var error by remember { mutableStateOf<String?>(null) }
    var challenge by remember { mutableStateOf<ParsedQr.OcraChallenge?>(null) }
    var candidates by remember { mutableStateOf<List<Token>>(emptyList()) }
    var response by remember { mutableStateOf<String?>(null) }

    error?.let { message ->
        LaunchedEffect(message) {
            snackbar.showSnackbar(message)
            error = null
        }
    }

    fun computeFor(token: Token, parsed: ParsedQr.OcraChallenge) {
        try {
            val suite = OcraSuite.parse(parsed.suite)
            response = Ocra.computeResponse(
                suite = suite,
                key = token.secret,
                question = parsed.q,
                unixTimeSeconds = if (suite.timeStepSeconds != null) {
                    System.currentTimeMillis() / 1000
                } else null,
            )
        } catch (e: IllegalArgumentException) {
            error = e.message
        }
    }

    fun onChallengeScanned(parsed: ParsedQr.OcraChallenge) {
        // Токени, чий профіль збігається з профілем виклику (FR-012)
        val matching = store.list().filter {
            it.type == TokenType.OCRA && it.ocraSuite == parsed.suite
        }
        when {
            matching.isEmpty() -> error = context.getString(R.string.ocra_no_token)
            matching.size == 1 -> {
                challenge = parsed
                computeFor(matching.first(), parsed)
            }
            else -> {
                challenge = parsed
                candidates = matching
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ocra_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        when {
            // 3. Відгук обчислено — показуємо великим шрифтом, тап копіює
            response != null -> Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(32.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(stringResource(R.string.ocra_response_label), style = MaterialTheme.typography.titleMedium)
                Text(
                    text = response.orEmpty().chunked(4).joinToString(" "),
                    style = MaterialTheme.typography.displayMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.clickable {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("", response.orEmpty()))
                        Toast.makeText(context, context.getString(R.string.ocra_copied), Toast.LENGTH_SHORT).show()
                    },
                )
                challenge?.let {
                    Text(
                        text = "Виклик: ${it.q}",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 16.dp),
                    )
                }
            }

            // 2. Кілька відповідних токенів — даємо вибрати
            candidates.isNotEmpty() -> Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(stringResource(R.string.ocra_pick_token), style = MaterialTheme.typography.titleMedium)
                candidates.forEach { token ->
                    Card(
                        modifier = Modifier.fillMaxWidth().clickable {
                            val parsed = challenge ?: return@clickable
                            candidates = emptyList()
                            computeFor(token, parsed)
                        },
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text(token.issuer, style = MaterialTheme.typography.titleMedium)
                            if (token.account.isNotBlank()) {
                                Text(token.account, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }

            // 1. Сканування виклику
            else -> Column(Modifier.fillMaxSize().padding(padding)) {
                Text(
                    text = stringResource(R.string.ocra_scan_hint),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(16.dp),
                )
                QrScanner(
                    onResult = { raw ->
                        try {
                            when (val parsed = OtpUri.parse(raw)) {
                                is ParsedQr.OcraChallenge -> onChallengeScanned(parsed)
                                // Користувач показав QR провіжинингу (Крок 1
                                // на стенді) — додаємо токен прямо тут, без
                                // переходу на екран «Додати токен»
                                is ParsedQr.OcraToken -> {
                                    val token = Token.fromParsed(parsed)
                                    val existing = store.findDuplicate(token)
                                    if (existing == null) store.save(token)
                                    error = context.getString(R.string.ocra_token_added, token.issuer)
                                }
                                else -> error = context.getString(R.string.scan_invalid_qr)
                            }
                        } catch (e: UriFormatException) {
                            error = e.message
                        } catch (e: IllegalArgumentException) {
                            error = e.message
                        }
                    },
                )
            }
        }
    }
}
