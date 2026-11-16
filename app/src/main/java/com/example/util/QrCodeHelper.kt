package com.example.util

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.net.Uri
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

object QrCodeHelper {

  fun generateQrBitmap(content: String, sizePx: Int = 640): Bitmap? {
    if (content.isBlank()) return null
    return try {
      val hints =
        mapOf(
          EncodeHintType.CHARACTER_SET to "UTF-8",
          EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
          EncodeHintType.MARGIN to 2,
        )
      val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
      val width = matrix.width
      val height = matrix.height
      val pixels = IntArray(width * height)
      val dark = Color.rgb(24, 24, 27)
      val light = Color.WHITE
      for (y in 0 until height) {
        val offset = y * width
        for (x in 0 until width) {
          pixels[offset + x] = if (matrix.get(x, y)) dark else light
        }
      }
      Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).apply {
        setPixels(pixels, 0, width, 0, 0, width, height)
      }
    } catch (_: Exception) {
      null
    }
  }

  fun decodeQrFromBitmap(bitmap: Bitmap): String? {
    val width = bitmap.width
    val height = bitmap.height
    if (width <= 0 || height <= 0) return null
    val pixels = IntArray(width * height)
    bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
    val source = RGBLuminanceSource(width, height, pixels)
    val hints =
      mapOf(
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.CHARACTER_SET to "UTF-8",
      )
    val reader = QRCodeReader()
    return try {
      reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (_: Exception) {
      try {
        reader.decode(BinaryBitmap(HybridBinarizer(source.invert())), hints).text
      } catch (_: Exception) {
        null
      }
    }
  }

  fun decodeQrFromUri(context: Context, uri: Uri): String? {
    return try {
      val boundsOpts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
      context.contentResolver.openInputStream(uri)?.use { stream ->
        BitmapFactory.decodeStream(stream, null, boundsOpts)
      }
      val maxDim = maxOf(boundsOpts.outWidth, boundsOpts.outHeight)
      var sampleSize = 1
      while (maxDim / sampleSize > 1280) {
        sampleSize *= 2
      }
      val decodeOpts = BitmapFactory.Options().apply { inSampleSize = sampleSize }
      val bmp =
        context.contentResolver.openInputStream(uri)?.use { stream ->
          BitmapFactory.decodeStream(stream, null, decodeOpts)
        } ?: return null
      try {
        decodeQrFromBitmap(bmp)
      } finally {
        bmp.recycle()
      }
    } catch (_: Exception) {
      null
    }
  }

  fun decodeQrFromYuvPlane(
    yBytes: ByteArray,
    width: Int,
    height: Int,
    rowStride: Int,
  ): String? {
    if (width <= 0 || height <= 0) return null
    val compact =
      if (rowStride == width) {
        yBytes
      } else {
        ByteArray(width * height).also { dst ->
          for (row in 0 until height) {
            val srcOffset = row * rowStride
            if (srcOffset + width <= yBytes.size) {
              System.arraycopy(yBytes, srcOffset, dst, row * width, width)
            }
          }
        }
      }
    val source = PlanarYUVLuminanceSource(compact, width, height, 0, 0, width, height, false)
    val hints = mapOf(DecodeHintType.TRY_HARDER to true)
    return try {
      QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (_: Exception) {
      null
    }
  }
}
