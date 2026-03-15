package com.securepasswd.mgmt.ui

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Base64
import android.util.Log
import android.view.ViewGroup
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.*
import com.google.zxing.common.HybridBinarizer
import java.util.*
import java.util.concurrent.Executors

@Composable
fun QRScannerView(
    onQrCodeScanned: (String) -> Unit,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
        )
    }

    val launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
        onResult = { granted ->
            hasCameraPermission = granted
            if (!granted) {
                onClose()
            }
        }
    )

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }

    if (hasCameraPermission) {
        Box(modifier = Modifier.fillMaxSize()) {
            AndroidView(
                factory = { ctx ->
                    val previewView = PreviewView(ctx).apply {
                        this.scaleType = PreviewView.ScaleType.FILL_CENTER
                        layoutParams = ViewGroup.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.MATCH_PARENT
                        )
                    }

                    val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                    cameraProviderFuture.addListener({
                        val cameraProvider = cameraProviderFuture.get()
                        val preview = Preview.Builder().build().also {
                            it.setSurfaceProvider(previewView.surfaceProvider)
                        }

                        // ZXing MultiFormatReader
                        val reader = MultiFormatReader().apply {
                            val hints = mutableMapOf<DecodeHintType, Any>()
                            hints[DecodeHintType.POSSIBLE_FORMATS] = EnumSet.of(BarcodeFormat.QR_CODE)
                            setHints(hints)
                        }

                        val analysisUseCase = ImageAnalysis.Builder()
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()

                        val executor = Executors.newSingleThreadExecutor()
                        analysisUseCase.setAnalyzer(executor) { imageProxy: ImageProxy ->
                            try {
                                val buffer = imageProxy.planes[0].buffer
                                val data = ByteArray(buffer.remaining())
                                buffer.get(data)

                                // ZXing requires a PlanarYUVLuminanceSource
                                val source = PlanarYUVLuminanceSource(
                                    data,
                                    imageProxy.width,
                                    imageProxy.height,
                                    0, 0,
                                    imageProxy.width,
                                    imageProxy.height,
                                    false
                                )
                                val bitmap = BinaryBitmap(HybridBinarizer(source))

                                try {
                                    val result = reader.decode(bitmap)
                                    onQrCodeScanned(result.text)
                                    cameraProvider.unbindAll()
                                } catch (e: NotFoundException) {
                                    // No QR code in this frame
                                } catch (e: Exception) {
                                    Log.e("QRScanner", "ZXing decode error", e)
                                }
                            } finally {
                                imageProxy.close()
                            }
                        }

                        val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
                        try {
                            cameraProvider.unbindAll()
                            cameraProvider.bindToLifecycle(
                                lifecycleOwner,
                                cameraSelector,
                                preview,
                                analysisUseCase
                            )
                        } catch (e: Exception) {
                            Log.e("QRScanner", "Use case binding failed", e)
                        }

                    }, ContextCompat.getMainExecutor(ctx))

                    previewView
                },
                modifier = Modifier.fillMaxSize()
            )

            IconButton(
                onClick = onClose,
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(16.dp)
                    .padding(top = 32.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Close Scanner",
                    tint = Color.White,
                    modifier = Modifier.size(32.dp)
                )
            }

            Text(
                "Scan TOTP QR Code",
                color = Color.White,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 64.dp),
                style = MaterialTheme.typography.titleMedium
            )
        }
    } else {
        // Wait for permission
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
    }
}

private fun readVarint(data: ByteArray, offset: IntArray): Long {
    var res = 0L
    var shift = 0
    while (offset[0] < data.size) {
        val b = data[offset[0]].toLong() and 0xFF
        offset[0]++
        res = res or ((b and 0x7F) shl shift)
        if ((b and 0x80) == 0L) {
            break
        }
        shift += 7
    }
    return res
}

private fun encodeBase32(bytes: ByteArray): String {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    val result = StringBuilder()
    var buffer = 0
    var bitsLeft = 0
    for (b in bytes) {
        buffer = (buffer shl 8) or (b.toInt() and 0xFF)
        bitsLeft += 8
        while (bitsLeft >= 5) {
            result.append(alphabet[(buffer ushr (bitsLeft - 5)) and 0x1F])
            bitsLeft -= 5
        }
    }
    if (bitsLeft > 0) {
        result.append(alphabet[(buffer shl (5 - bitsLeft)) and 0x1F])
    }
    return result.toString()
}

private fun decodeMigrationPayload(base64Data: String): String? {
    try {
        val decoded = Base64.decode(base64Data, Base64.URL_SAFE)
        val offset = intArrayOf(0)
        while (offset[0] < decoded.size) {
            val tagVal = readVarint(decoded, offset)
            val tag = tagVal shr 3
            val wireType = (tagVal and 7).toInt()

            if (wireType == 2) {
                val length = readVarint(decoded, offset).toInt()
                val start = offset[0]
                offset[0] += length

                if (tag == 1L) {
                    // This is the MigrationPayload.otp_parameters repeated field
                    val innerOffset = intArrayOf(start)
                    while (innerOffset[0] < start + length) {
                        val innerTagVal = readVarint(decoded, innerOffset)
                        val innerTag = innerTagVal shr 3
                        val innerWireType = (innerTagVal and 7).toInt()

                        if (innerWireType == 2) {
                            val innerLength = readVarint(decoded, innerOffset).toInt()
                            val innerStart = innerOffset[0]
                            innerOffset[0] += innerLength

                            if (innerTag == 1L) {
                                // This is the secret byte array
                                val secretBytes = decoded.sliceArray(innerStart until innerStart + innerLength)
                                return encodeBase32(secretBytes)
                            }
                        } else if (innerWireType == 0) {
                            readVarint(decoded, innerOffset)
                        }
                    }
                }
            } else if (wireType == 0) {
                readVarint(decoded, offset)
            }
        }
    } catch (e: Exception) {
        Log.e("QRScanner", "Failed to parse migration payload", e)
    }
    return null
}
