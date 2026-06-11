package ua.authapp.scanner

import android.Manifest
import android.content.pm.PackageManager
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import ua.authapp.R
import java.util.concurrent.Executors

/**
 * Сканер QR-кодів: CameraX (прев'ю + аналіз кадрів) + ML Kit on-device.
 * Працює повністю офлайн; кадри нікуди не передаються. Відмова в дозволі
 * камери пояснюється користувачеві (edge case специфікації).
 *
 * Кожне РІЗНЕ значення доставляється рівно один раз: після помилкового QR
 * сканер продовжує працювати, а повтори того самого коду не спамлять
 * обробника. Унизу — діагностична панель: лічильник проаналізованих кадрів
 * (конвеєр живий) і підтвердження розпізнавання.
 */
@Composable
fun QrScanner(onResult: (String) -> Unit) {
    val context = LocalContext.current
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    var permissionDenied by remember { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasPermission = granted
        permissionDenied = !granted
    }

    LaunchedEffect(Unit) {
        if (!hasPermission) launcher.launch(Manifest.permission.CAMERA)
    }

    when {
        hasPermission -> CameraPreview(onResult)
        permissionDenied -> PermissionMessage(R.string.scan_permission_denied)
        else -> PermissionMessage(R.string.scan_permission_rationale)
    }
}

@Composable
private fun PermissionMessage(textRes: Int) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(textRes), textAlign = TextAlign.Center)
    }
}

@Composable
private fun CameraPreview(onResult: (String) -> Unit) {
    val lifecycleOwner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val scanner = remember {
        BarcodeScanning.getClient(
            BarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                .build(),
        )
    }
    // Кожне різне значення — рівно одна доставка
    val seenValues = remember { mutableSetOf<String>() }

    // Діагностика: чи живий конвеєр аналізу і чи розпізнаються коди
    var framesAnalyzed by remember { mutableIntStateOf(0) }
    var lastDetectedAt by remember { mutableLongStateOf(0L) }
    var bindError by remember { mutableStateOf<String?>(null) }

    DisposableEffect(Unit) {
        onDispose {
            executor.shutdown()
            scanner.close()
        }
    }

    Box(Modifier.fillMaxSize()) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val providerFuture = ProcessCameraProvider.getInstance(ctx)
                providerFuture.addListener({
                    try {
                        val provider = providerFuture.get()
                        val preview = Preview.Builder().build().apply {
                            surfaceProvider = previewView.surfaceProvider
                        }
                        val analysis = ImageAnalysis.Builder()
                            // 1280×720 — удвічі краще за типові 640×480 для
                            // щільних QR і в межах гарантованих конфігурацій
                            // камер (FullHD на частині пристроїв мовчки
                            // зупиняв доставку кадрів аналізатору)
                            .setResolutionSelector(
                                ResolutionSelector.Builder()
                                    .setResolutionStrategy(
                                        ResolutionStrategy(
                                            Size(1280, 720),
                                            ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                                        ),
                                    )
                                    .build(),
                            )
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()
                        var rawFrames = 0
                        analysis.setAnalyzer(executor) { imageProxy ->
                            // Оновлюємо лічильник раз на 5 кадрів, щоб не
                            // влаштовувати рекомпозицію на кожному кадрі
                            rawFrames++
                            if (rawFrames % 5 == 0) framesAnalyzed = rawFrames
                            processFrame(scanner, imageProxy) { value ->
                                lastDetectedAt = System.currentTimeMillis()
                                if (seenValues.add(value)) onResult(value)
                            }
                        }
                        provider.unbindAll()
                        provider.bindToLifecycle(
                            lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis,
                        )
                    } catch (e: Exception) {
                        // Конфігурація камери не вдалася — показуємо причину
                        bindError = e.message ?: e.javaClass.simpleName
                    }
                }, ContextCompat.getMainExecutor(ctx))
                previewView
            },
        )

        // Діагностична панель сканера
        Surface(
            modifier = Modifier.align(Alignment.BottomCenter).fillMaxWidth(),
            color = MaterialTheme.colorScheme.surface.copy(alpha = 0.85f),
        ) {
            val detectedRecently =
                System.currentTimeMillis() - lastDetectedAt < 1500 && lastDetectedAt > 0
            Text(
                text = when {
                    bindError != null -> stringResource(R.string.scan_camera_error, bindError.orEmpty())
                    detectedRecently -> stringResource(R.string.scan_detected)
                    framesAnalyzed == 0 -> stringResource(R.string.scan_starting)
                    else -> stringResource(R.string.scan_searching, framesAnalyzed)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = if (bindError != null) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(12.dp),
            )
        }
    }
}

private fun processFrame(
    scanner: com.google.mlkit.vision.barcode.BarcodeScanner,
    imageProxy: ImageProxy,
    onQr: (String) -> Unit,
) {
    @androidx.camera.core.ExperimentalGetImage
    val mediaImage = imageProxy.image
    if (mediaImage == null) {
        imageProxy.close()
        return
    }
    val input = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
    scanner.process(input)
        .addOnSuccessListener { barcodes ->
            barcodes.firstOrNull()?.rawValue?.let(onQr)
        }
        .addOnCompleteListener { imageProxy.close() }
}
