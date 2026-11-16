package com.example.ui.components

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CameraAlt
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.PhotoLibrary
import androidx.compose.material.icons.rounded.QrCode2
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.example.model.VpnConfig
import com.example.ui.strings.LocalAppStrings
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.util.QrCodeHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun QrExportDialog(
  profile: VpnConfig,
  shareUri: String,
  onCopyUri: () -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppStrings.current
  val context = LocalContext.current
  val qrBitmap = remember(shareUri) { QrCodeHelper.generateQrBitmap(shareUri, sizePx = 640) }

  Dialog(onDismissRequest = onDismiss) {
    Card(
      shape = MaterialTheme.shapes.large,
      colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
      border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
      modifier = Modifier.fillMaxWidth(),
    ) {
      Column(
        modifier = Modifier.padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
      ) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
          ) {
            Icon(
              imageVector = Icons.Rounded.QrCode2,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.primary,
            )
            Text(
              text = strings.qrExportTitle,
              style = MaterialTheme.typography.titleMedium,
              color = MaterialTheme.colorScheme.onSurface,
            )
          }
          IconButton(
            onClick = onDismiss,
            modifier = Modifier.minimumInteractiveComponentSize(),
          ) {
            Icon(Icons.Rounded.Close, contentDescription = strings.cancel)
          }
        }

        Text(
          text = profile.name,
          style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
          color = MaterialTheme.colorScheme.primary,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )

        // Always keep a crisp white quiet-zone card behind the QR code for reliable camera scanning
        Surface(
          color = Color.White,
          shape = MaterialTheme.shapes.medium,
          border = BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)),
          modifier = Modifier.size(230.dp),
        ) {
          Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.fillMaxSize().padding(12.dp),
          ) {
            if (qrBitmap != null) {
              Image(
                bitmap = qrBitmap.asImageBitmap(),
                contentDescription = strings.qrExportTitle,
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize(),
              )
            }
          }
        }

        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
          Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = shareUri,
              style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily),
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              maxLines = 2,
              overflow = TextOverflow.Ellipsis,
              modifier = Modifier.padding(10.dp),
            )
          }
        }

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
          Button(
            onClick = onCopyUri,
            modifier = Modifier.weight(1f).minimumInteractiveComponentSize().testTag("qr_copy_button"),
          ) {
            Icon(Icons.Rounded.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.exportConfig, maxLines = 1, overflow = TextOverflow.Ellipsis)
          }

          OutlinedButton(
            onClick = {
              val sendIntent =
                Intent(Intent.ACTION_SEND).apply {
                  type = "text/plain"
                  putExtra(Intent.EXTRA_TEXT, shareUri)
                }
              context.startActivity(Intent.createChooser(sendIntent, strings.shareConfig))
            },
            modifier = Modifier.minimumInteractiveComponentSize().testTag("qr_share_button"),
          ) {
            Icon(Icons.Rounded.Share, contentDescription = strings.shareConfig, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.shareConfig)
          }
        }
      }
    }
  }
}

@Composable
fun QrScannerDialog(
  onScannedText: (String) -> Unit,
  onPasteClipboard: () -> Unit,
  onScanFailed: (String) -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppStrings.current
  val context = LocalContext.current
  val scope = rememberCoroutineScope()

  var hasCameraPermission by remember {
    mutableStateOf(
      ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
        PackageManager.PERMISSION_GRANTED
    )
  }

  val cameraPermissionLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
      hasCameraPermission = granted
    }

  val photoPickerLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
      if (uri != null) {
        scope.launch {
          val decoded = withContext(Dispatchers.IO) { QrCodeHelper.decodeQrFromUri(context, uri) }
          if (!decoded.isNullOrBlank()) {
            onScannedText(decoded)
          } else {
            onScanFailed(strings.qrNoCodeFound)
          }
        }
      }
    }

  Dialog(
    onDismissRequest = onDismiss,
    properties = DialogProperties(usePlatformDefaultWidth = false),
  ) {
    Card(
      shape = MaterialTheme.shapes.large,
      colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
      border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
      modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
    ) {
      Column(
        modifier = Modifier.padding(18.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
      ) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
          ) {
            Icon(
              imageVector = Icons.Rounded.QrCode2,
              contentDescription = null,
              tint = MaterialTheme.colorScheme.primary,
            )
            Text(
              text = strings.scanQrTitle,
              style = MaterialTheme.typography.titleMedium,
              color = MaterialTheme.colorScheme.onSurface,
            )
          }
          IconButton(
            onClick = onDismiss,
            modifier = Modifier.minimumInteractiveComponentSize(),
          ) {
            Icon(Icons.Rounded.Close, contentDescription = strings.cancel)
          }
        }

        Box(
          contentAlignment = Alignment.Center,
          modifier =
            Modifier
              .fillMaxWidth()
              .aspectRatio(1f)
              .clip(RoundedCornerShape(18.dp))
              .background(Color(0xFF141210)),
        ) {
          if (hasCameraPermission) {
            CameraQrPreview(
              onDecoded = onScannedText,
              modifier = Modifier.fillMaxSize(),
            )
            val cornerColor = MaterialTheme.colorScheme.primary
            Canvas(modifier = Modifier.fillMaxSize().padding(34.dp)) {
              val len = size.minDimension * 0.18f
              val stroke = 4.dp.toPx()
              // Top-left
              drawLine(cornerColor, Offset(0f, 0f), Offset(len, 0f), stroke, StrokeCap.Round)
              drawLine(cornerColor, Offset(0f, 0f), Offset(0f, len), stroke, StrokeCap.Round)
              // Top-right
              drawLine(cornerColor, Offset(size.width - len, 0f), Offset(size.width, 0f), stroke, StrokeCap.Round)
              drawLine(cornerColor, Offset(size.width, 0f), Offset(size.width, len), stroke, StrokeCap.Round)
              // Bottom-left
              drawLine(cornerColor, Offset(0f, size.height), Offset(len, size.height), stroke, StrokeCap.Round)
              drawLine(cornerColor, Offset(0f, size.height - len), Offset(0f, size.height), stroke, StrokeCap.Round)
              // Bottom-right
              drawLine(
                cornerColor,
                Offset(size.width - len, size.height),
                Offset(size.width, size.height),
                stroke,
                StrokeCap.Round,
              )
              drawLine(
                cornerColor,
                Offset(size.width, size.height - len),
                Offset(size.width, size.height),
                stroke,
                StrokeCap.Round,
              )
            }
          } else {
            Column(
              modifier = Modifier.padding(24.dp),
              horizontalAlignment = Alignment.CenterHorizontally,
              verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
              Icon(
                imageVector = Icons.Rounded.CameraAlt,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(44.dp),
              )
              Text(
                text = strings.cameraPermissionHint,
                style = MaterialTheme.typography.bodyMedium,
                color = Color.White,
                textAlign = TextAlign.Center,
              )
              Button(
                onClick = { cameraPermissionLauncher.launch(Manifest.permission.CAMERA) },
                colors =
                  ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                  ),
                modifier = Modifier.minimumInteractiveComponentSize().testTag("grant_camera_button"),
              ) {
                Text(strings.enableCamera)
              }
            }
          }
        }

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
          FilledTonalButton(
            onClick = {
              photoPickerLauncher.launch(
                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
              )
            },
            modifier = Modifier.weight(1f).minimumInteractiveComponentSize().testTag("qr_pick_gallery_button"),
          ) {
            Icon(Icons.Rounded.PhotoLibrary, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.pickQrImage, maxLines = 1, overflow = TextOverflow.Ellipsis)
          }

          OutlinedButton(
            onClick = onPasteClipboard,
            modifier = Modifier.weight(1f).minimumInteractiveComponentSize().testTag("qr_paste_clipboard_button"),
          ) {
            Icon(Icons.Rounded.ContentPaste, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(strings.importClipboard, maxLines = 1, overflow = TextOverflow.Ellipsis)
          }
        }

        TextButton(onClick = onDismiss) {
          Text(strings.cancel)
        }
      }
    }
  }
}

@Composable
private fun CameraQrPreview(
  onDecoded: (String) -> Unit,
  modifier: Modifier = Modifier,
) {
  val context = LocalContext.current
  val lifecycleOwner = LocalLifecycleOwner.current
  val analyzerExecutor = remember { Executors.newSingleThreadExecutor() }
  val handled = remember { AtomicBoolean(false) }
  val previewView = remember {
    PreviewView(context).apply {
      scaleType = PreviewView.ScaleType.FILL_CENTER
    }
  }

  DisposableEffect(lifecycleOwner) {
    val providerFuture = ProcessCameraProvider.getInstance(context)
    val mainExecutor = ContextCompat.getMainExecutor(context)

    val listener = Runnable {
      val provider = runCatching { providerFuture.get() }.getOrNull() ?: return@Runnable
      val preview =
        Preview.Builder().build().apply {
          surfaceProvider = previewView.surfaceProvider
        }
      val analysis =
        ImageAnalysis.Builder()
          .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
          .build()
          .apply {
            setAnalyzer(analyzerExecutor) { imageProxy ->
              try {
                if (handled.get()) return@setAnalyzer
                val plane = imageProxy.planes.firstOrNull() ?: return@setAnalyzer
                val buffer = plane.buffer
                val bytes = ByteArray(buffer.remaining())
                buffer.get(bytes)
                val decoded =
                  QrCodeHelper.decodeQrFromYuvPlane(
                    yBytes = bytes,
                    width = imageProxy.width,
                    height = imageProxy.height,
                    rowStride = plane.rowStride,
                  )
                if (!decoded.isNullOrBlank() && handled.compareAndSet(false, true)) {
                  mainExecutor.execute { onDecoded(decoded) }
                }
              } finally {
                imageProxy.close()
              }
            }
          }

      runCatching {
        provider.unbindAll()
        provider.bindToLifecycle(
          lifecycleOwner,
          CameraSelector.DEFAULT_BACK_CAMERA,
          preview,
          analysis,
        )
      }
    }

    providerFuture.addListener(listener, mainExecutor)

    onDispose {
      runCatching {
        if (providerFuture.isDone) {
          providerFuture.get().unbindAll()
        }
      }
      analyzerExecutor.shutdown()
    }
  }

  AndroidView(
    factory = { previewView },
    modifier = modifier,
  )
}
