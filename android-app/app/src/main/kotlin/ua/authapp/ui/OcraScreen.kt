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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import ua.authapp.AuthApplication
import ua.authapp.R
import ua.authapp.crypto.codec.OtpUri
import ua.authapp.crypto.codec.ParsedQr
import ua.authapp.crypto.codec.UriFormatException
import ua.authapp.crypto.ocra.Ocra
import ua.authapp.crypto.ocra.OcraInputs
import ua.authapp.crypto.ocra.OcraSuite
import ua.authapp.scanner.QrScanner
import ua.authapp.storage.Token
import ua.authapp.storage.TokenType

/** Очікуване обчислення: зібрані входи + контекст для показу результату. */
private data class PendingComputation(
    val token: Token,
    val clientSuite: OcraSuite,
    /** Питання для відповіді клієнта (mutual: QS‖QC) */
    val question: String,
    val counter: Long?,
    val sessionInfo: ByteArray?,
    /** Підпис транзакції: текст транзакції для показу */
    val transaction: String?,
    /** Взаємна автентифікація: сервер уже верифіковано */
    val serverVerified: Boolean,
)

/** Результат для відображення. */
private data class OcraResult(
    val response: String,
    val transaction: String?,
    val serverVerified: Boolean,
)

/**
 * Екран OCRA (US3; FR-012, FR-027): сканування виклику → [PIN за потреби] →
 * відгук. Підтримує односторонні профілі (C/P/S/T), взаємну автентифікацію
 * (спершу верифікується сервер) і підпис транзакцій (текст транзакції
 * показується перед підписом).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OcraScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val store = (context.applicationContext as AuthApplication).tokenStore
    val snackbar = remember { SnackbarHostState() }

    var error by remember { mutableStateOf<String?>(null) }
    var candidates by remember { mutableStateOf<List<Token>>(emptyList()) }
    var candidateChallenge by remember { mutableStateOf<ParsedQr?>(null) }
    var pending by remember { mutableStateOf<PendingComputation?>(null) }
    var pinPrompt by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<OcraResult?>(null) }

    error?.let { message ->
        LaunchedEffect(message) {
            snackbar.showSnackbar(message)
            error = null
        }
    }

    fun complete(computation: PendingComputation, pinHash: ByteArray?) {
        try {
            val response = Ocra.computeResponse(
                computation.clientSuite,
                computation.token.secret,
                OcraInputs(
                    question = computation.question,
                    counter = computation.counter,
                    pinHash = pinHash,
                    sessionInfo = computation.sessionInfo,
                    unixTimeSeconds = if (computation.clientSuite.timeStepSeconds != null) {
                        System.currentTimeMillis() / 1000
                    } else null,
                ),
            )
            result = OcraResult(response, computation.transaction, computation.serverVerified)
            pending = null
        } catch (e: IllegalArgumentException) {
            error = e.message
            pending = null
        }
    }

    fun launch(computation: PendingComputation) {
        if (computation.clientSuite.pinHashAlgorithm != null) {
            pending = computation
            pinPrompt = true
        } else {
            complete(computation, pinHash = null)
        }
    }

    fun startSingle(token: Token, challenge: ParsedQr.OcraChallenge) {
        try {
            val suite = OcraSuite.parse(challenge.suite)
            launch(
                PendingComputation(
                    token = token,
                    clientSuite = suite,
                    question = challenge.q,
                    counter = challenge.counter,
                    sessionInfo = challenge.sessionB64?.let {
                        java.util.Base64.getUrlDecoder().decode(it)
                    },
                    transaction = if (challenge.mode == "sign") challenge.q else null,
                    serverVerified = false,
                ),
            )
        } catch (e: IllegalArgumentException) {
            error = e.message
        }
    }

    fun startMutual(token: Token, challenge: ParsedQr.OcraMutualChallenge) {
        try {
            // Крок 1: клієнт верифікує сервер — відгук сервера на Q = QC ‖ QS
            val serverSuite = OcraSuite.parse(challenge.serverSuite)
            val serverOk = Ocra.verifyResponse(
                serverSuite, token.secret,
                OcraInputs(question = challenge.qc + challenge.qs),
                challenge.serverResponse,
            )
            if (!serverOk) {
                error = context.getString(R.string.ocra_server_invalid)
                return
            }
            // Крок 2: відповідь клієнта на Q = QS ‖ QC
            launch(
                PendingComputation(
                    token = token,
                    clientSuite = OcraSuite.parse(challenge.clientSuite),
                    question = challenge.qs + challenge.qc,
                    counter = null,
                    sessionInfo = null,
                    transaction = null,
                    serverVerified = true,
                ),
            )
        } catch (e: IllegalArgumentException) {
            error = e.message
        }
    }

    fun dispatch(token: Token, parsed: ParsedQr) {
        when (parsed) {
            is ParsedQr.OcraChallenge -> startSingle(token, parsed)
            is ParsedQr.OcraMutualChallenge -> startMutual(token, parsed)
            else -> error = context.getString(R.string.scan_invalid_qr)
        }
    }

    fun onScanned(parsed: ParsedQr) {
        val requiredSuite = when (parsed) {
            is ParsedQr.OcraChallenge -> parsed.suite
            is ParsedQr.OcraMutualChallenge -> parsed.clientSuite
            is ParsedQr.OcraToken -> {
                val token = Token.fromParsed(parsed)
                if (store.findDuplicate(token) == null) store.save(token)
                error = context.getString(R.string.ocra_token_added, token.issuer)
                return
            }
            else -> {
                error = context.getString(R.string.scan_invalid_qr)
                return
            }
        }
        val matching = store.list().filter {
            it.type == TokenType.OCRA && it.ocraSuite == requiredSuite
        }
        when {
            matching.isEmpty() -> error = context.getString(R.string.ocra_no_token)
            matching.size == 1 -> dispatch(matching.first(), parsed)
            else -> {
                candidates = matching
                candidateChallenge = parsed
            }
        }
    }

    // PIN-діалог для P-профілів
    if (pinPrompt) {
        var pin by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = {
                pinPrompt = false
                pending = null
            },
            title = { Text(stringResource(R.string.ocra_pin_title)) },
            text = {
                Column {
                    Text(stringResource(R.string.ocra_pin_hint))
                    OutlinedTextField(
                        value = pin,
                        onValueChange = { pin = it },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = pin.isNotBlank(),
                    onClick = {
                        val computation = pending ?: return@TextButton
                        val pinHash = Ocra.hashPin(
                            pin, requireNotNull(computation.clientSuite.pinHashAlgorithm),
                        )
                        pinPrompt = false
                        complete(computation, pinHash)
                    },
                ) { Text(stringResource(R.string.action_ok)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    pinPrompt = false
                    pending = null
                }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
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
            // 3. Результат: відгук/підпис із контекстом
            result != null -> Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(32.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                val current = result ?: return@Column
                if (current.serverVerified) {
                    Text(
                        text = stringResource(R.string.ocra_server_verified),
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(bottom = 16.dp),
                    )
                }
                current.transaction?.let {
                    Text(
                        text = stringResource(R.string.ocra_transaction, it),
                        style = MaterialTheme.typography.titleMedium,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(bottom = 16.dp),
                    )
                }
                Text(
                    text = stringResource(
                        if (current.transaction != null) R.string.ocra_sign_response_label
                        else R.string.ocra_response_label,
                    ),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = groupCode(current.response),
                    style = MaterialTheme.typography.displayMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.clickable {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("", current.response))
                        Toast.makeText(context, context.getString(R.string.ocra_copied), Toast.LENGTH_SHORT).show()
                    },
                )
            }

            // 2. Кілька відповідних токенів — вибір
            candidates.isNotEmpty() -> Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(stringResource(R.string.ocra_pick_token), style = MaterialTheme.typography.titleMedium)
                candidates.forEach { token ->
                    Card(
                        modifier = Modifier.fillMaxWidth().clickable {
                            val challenge = candidateChallenge ?: return@clickable
                            candidates = emptyList()
                            dispatch(token, challenge)
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
                            onScanned(OtpUri.parse(raw))
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
