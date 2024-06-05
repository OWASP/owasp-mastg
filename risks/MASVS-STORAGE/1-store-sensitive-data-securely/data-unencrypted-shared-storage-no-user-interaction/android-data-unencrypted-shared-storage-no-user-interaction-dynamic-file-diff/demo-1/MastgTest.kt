package org.owasp.mastestapp

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import android.content.ContentValues
import android.os.Environment
import android.provider.MediaStore
import java.io.OutputStream

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        mastgTestApi()
        mastgTestMediaStore()
        return "SUCCESS!!\n\nFiles have been written with API and MediaStore"
    }
    fun mastgTestApi() {
        val externalStorageDir = context.getExternalFilesDir(null)
        val fileName = File(externalStorageDir, "secret.txt")
        val fileContent = "Secret may use scoped storage depending on Android version"

        try {
            FileOutputStream(fileName).use { output ->
                output.write(fileContent.toByteArray())
                Log.d("WriteExternalStorage", "File written to external storage successfully.")
            }
        } catch (e: IOException) {
            Log.e("WriteExternalStorage", "Error writing file to external storage", e)
        }
    }

    fun mastgTestMediaStore() {
        try {
            val resolver = context.contentResolver
            var randomNum = (0..100).random().toString()
            val contentValues = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, "secretFile$randomNum.txt")
                put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
            val textUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)

            textUri?.let {
                val outputStream: OutputStream? = resolver.openOutputStream(it)
                outputStream?.use {
                    it.write("Secret data".toByteArray())
                    it.flush()
                }
                Log.d("MediaStore", "File written to external storage successfully.")
            } ?: run {
                Log.e("MediaStore", "Error inserting URI to MediaStore.")
            }
        } catch (exception: Exception) {
            Log.e("MediaStore", "Error writing file to URI from MediaStore", exception)
        }
    }
}

