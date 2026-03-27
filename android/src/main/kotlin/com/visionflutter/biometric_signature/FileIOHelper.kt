package com.visionflutter.biometric_signature

import android.content.Context
import java.io.File

class FileIOHelper(private val appContext: Context) {
    fun writeFileAtomic(fileName: String, data: ByteArray) {
        val target = File(appContext.filesDir, fileName)
        val tmp = File(appContext.filesDir, "$fileName.tmp")
        tmp.outputStream().use { it.write(data) }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw IllegalStateException("Failed to atomically write $fileName")
        }
    }

    fun readFileIfExists(fileName: String): ByteArray? {
        val file = File(appContext.filesDir, fileName)
        return if (!file.exists()) null else file.readBytes()
    }
}
