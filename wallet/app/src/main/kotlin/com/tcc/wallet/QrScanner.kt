package com.tcc.wallet

import android.Manifest
import android.content.pm.PackageManager
import androidx.annotation.OptIn
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.tcc.wallet.ui.components.CircleIconButton
import com.tcc.wallet.ui.components.PrimaryButton
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletType
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Full-screen QR scanner. CameraX feeds frames to ML Kit's *bundled*
 * QR decoder; the first decoded value is handed to [onResult] verbatim, so the caller
 * can route it straight into the existing `OfferLink.resolve` / `Oid4vpPresenter`
 * entry points. Nothing here is SSI-specific — it just turns the camera into a string.
 *
 * Camera scanning is a convenience: pasting a link and arriving via an
 * `openid-credential-offer://` / `openid4vp://` deep link remain as fallbacks, so the
 * CAMERA permission is optional (manifest `required="false"`).
 */
private enum class CamPerm { PENDING, GRANTED, DENIED }

@Composable
fun QrScanner(onResult: (String) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    var perm by remember {
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        mutableStateOf(if (granted) CamPerm.GRANTED else CamPerm.PENDING)
    }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> perm = if (granted) CamPerm.GRANTED else CamPerm.DENIED }

    // Camera-first, but a link can be pasted instead (the "or get the URL" path).
    var pasteMode by remember { mutableStateOf(false) }
    var pasted by remember { mutableStateOf("") }

    // Ask once on first show if we don't already hold the permission.
    LaunchedEffect(Unit) {
        if (perm == CamPerm.PENDING) launcher.launch(Manifest.permission.CAMERA)
    }

    Box(Modifier.fillMaxSize().background(WalletColors.ScannerDark)) {
        when (perm) {
            CamPerm.GRANTED -> CameraPreview(onResult = onResult)
            CamPerm.PENDING -> CenteredHint("Requesting camera permission…")
            CamPerm.DENIED -> CenteredHint(
                "Camera permission denied. Grant it in system settings, or go back and paste the link instead.",
            )
        }

        // Soft radial indigo glow behind the reticle.
        Box(
            Modifier.fillMaxSize().background(
                Brush.radialGradient(
                    colors = listOf(WalletColors.Brand.copy(alpha = 0.18f), Color.Transparent),
                    radius = 700f,
                ),
            ),
        )

        // Header: close + title.
        Row(
            Modifier.fillMaxWidth().align(Alignment.TopStart).padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            CircleIconButton(
                Icons.Rounded.Close,
                contentDescription = "Close scanner",
                background = Color.White.copy(alpha = 0.12f),
                tint = Color.White,
                onClick = onCancel,
            )
            Text("Scan QR code", style = WalletType.headerTitle.copy(color = Color.White))
        }

        // Center reticle with animated scan line.
        Reticle(Modifier.align(Alignment.Center))

        // Footer: helper text + paste fallback (or the paste panel when toggled on).
        Column(
            Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .padding(start = 24.dp, end = 24.dp, bottom = 40.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (pasteMode) {
                OutlinedTextField(
                    value = pasted,
                    onValueChange = { pasted = it },
                    placeholder = { Text("openid-credential-offer:// or openid4vp://") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        cursorColor = Color.White,
                        focusedBorderColor = WalletColors.Brand2,
                        unfocusedBorderColor = Color.White.copy(alpha = 0.4f),
                    ),
                )
                Spacer(Modifier.height(12.dp))
                PrimaryButton(
                    "Continue",
                    Modifier.fillMaxWidth(),
                    enabled = pasted.isNotBlank(),
                    onClick = { onResult(pasted.trim()) },
                )
            } else {
                Text(
                    "Point your camera at the verifier or issuer QR code",
                    style = WalletType.bodySmall.copy(color = Color.White.copy(alpha = 0.7f)),
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(14.dp))
                Text(
                    "Paste link instead",
                    style = WalletType.bodySmall.copy(color = Color.White),
                    modifier = Modifier.clickable { pasteMode = true }.padding(8.dp),
                )
            }
        }
    }
}

@Composable
private fun CenteredHint(text: String) {
    Box(Modifier.fillMaxSize().padding(40.dp), contentAlignment = Alignment.Center) {
        Text(text, style = WalletType.bodySmall.copy(color = Color.White.copy(alpha = 0.8f)), textAlign = TextAlign.Center)
    }
}

/** The 236dp framing reticle: four indigo corner brackets + a looping scan line. */
@Composable
private fun Reticle(modifier: Modifier = Modifier) {
    val transition = rememberInfiniteTransition(label = "scan")
    val pos by transition.animateFloat(
        initialValue = 0.06f,
        targetValue = 0.94f,
        animationSpec = infiniteRepeatable(tween(2400, easing = LinearEasing), RepeatMode.Reverse),
        label = "scanline",
    )
    Box(modifier.size(236.dp)) {
        Canvas(Modifier.fillMaxSize()) {
            val bracket = 42.dp.toPx()
            val stroke = 4.dp.toPx()
            val c = WalletColors.Brand2
            // top-left
            corner(Offset(0f, 0f), bracket, stroke, c, right = true, down = true)
            // top-right
            corner(Offset(size.width, 0f), bracket, stroke, c, right = false, down = true)
            // bottom-left
            corner(Offset(0f, size.height), bracket, stroke, c, right = true, down = false)
            // bottom-right
            corner(Offset(size.width, size.height), bracket, stroke, c, right = false, down = false)

            // Scan line.
            val y = size.height * pos
            drawLine(
                brush = Brush.horizontalGradient(
                    listOf(Color.Transparent, WalletColors.Brand2, Color.Transparent),
                ),
                start = Offset(0f, y),
                end = Offset(size.width, y),
                strokeWidth = 2.dp.toPx(),
                cap = StrokeCap.Round,
            )
        }
    }
}

/** Draw one L-shaped corner bracket from [origin] extending [len] along each edge. */
private fun androidx.compose.ui.graphics.drawscope.DrawScope.corner(
    origin: Offset,
    len: Float,
    stroke: Float,
    color: Color,
    right: Boolean,
    down: Boolean,
) {
    val dx = if (right) len else -len
    val dy = if (down) len else -len
    drawLine(color, origin, Offset(origin.x + dx, origin.y), strokeWidth = stroke, cap = StrokeCap.Round)
    drawLine(color, origin, Offset(origin.x, origin.y + dy), strokeWidth = stroke, cap = StrokeCap.Round)
}

@Composable
private fun CameraPreview(onResult: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
    // Fire exactly once: ML Kit can decode the same QR on many consecutive frames.
    val handled = remember { AtomicBoolean(false) }
    val scanner = remember {
        BarcodeScanning.getClient(
            BarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                .build(),
        )
    }
    // Cache the resolved provider so onDispose can unbind without a redundant blocking get().
    val providerRef = remember { arrayOfNulls<ProcessCameraProvider>(1) }

    DisposableEffect(Unit) {
        onDispose {
            // Lifecycle outlives this composable (single-activity app), so unbind explicitly.
            providerRef[0]?.unbindAll()
            analysisExecutor.shutdown()
            scanner.close()
        }
    }

    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { ctx ->
            val previewView = PreviewView(ctx)
            val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
            cameraProviderFuture.addListener({
                val cameraProvider = cameraProviderFuture.get()
                providerRef[0] = cameraProvider
                val preview = Preview.Builder().build().also {
                    it.setSurfaceProvider(previewView.surfaceProvider)
                }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                    .also { it.setAnalyzer(analysisExecutor) { proxy -> scan(proxy, scanner, handled, onResult) } }
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            }, ContextCompat.getMainExecutor(ctx))
            previewView
        },
    )
}

@OptIn(ExperimentalGetImage::class)
private fun scan(
    imageProxy: ImageProxy,
    scanner: BarcodeScanner,
    handled: AtomicBoolean,
    onResult: (String) -> Unit,
) {
    val mediaImage = imageProxy.image
    if (mediaImage == null || handled.get()) {
        imageProxy.close()
        return
    }
    val input = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
    scanner.process(input)
        .addOnSuccessListener { barcodes ->
            val value = barcodes.firstOrNull()?.rawValue
            // compareAndSet guarantees onResult runs only for the first frame that decodes.
            if (value != null && handled.compareAndSet(false, true)) onResult(value)
        }
        .addOnCompleteListener { imageProxy.close() }
}
