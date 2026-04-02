package com.visionflutter.biometric_signature

import android.util.Base64

object FormatUtils {
    data class FormattedOutput(
        val value: String,
        val format: KeyFormat,
        val pemLabel: String? = null
    )

    fun formatOutput(
        bytes: ByteArray,
        format: KeyFormat,
        label: String = "PUBLIC KEY"
    ): FormattedOutput =
        when (format) {
            KeyFormat.BASE64 -> FormattedOutput(
                Base64.encodeToString(bytes, Base64.NO_WRAP),
                format
            )
            KeyFormat.PEM -> FormattedOutput(
                "-----BEGIN $label-----\n${
                    Base64.encodeToString(bytes, Base64.NO_WRAP).chunked(64).joinToString("\n")
                }\n-----END $label-----",
                format,
                label
            )
            KeyFormat.HEX -> FormattedOutput(bytesToHex(bytes), format)
            KeyFormat.RAW -> FormattedOutput(Base64.encodeToString(bytes, Base64.NO_WRAP), format)
        }

    fun parsePayload(payload: String, format: PayloadFormat): ByteArray {
        return when (format) {
            PayloadFormat.BASE64, PayloadFormat.RAW -> Base64.decode(payload, Base64.NO_WRAP)
            PayloadFormat.HEX -> hexToBytes(payload)
        }
    }

    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun hexToBytes(hex: String): ByteArray {
        val cleanHex = if (hex.length % 2 != 0) "0$hex" else hex
        return cleanHex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
