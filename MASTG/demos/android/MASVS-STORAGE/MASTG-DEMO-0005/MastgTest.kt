package org.owasp.mastestapp

import android.content.ContentValues
import android.util.Log
import android.content.Context
import android.os.Environment
import android.provider.MediaStore
import java.io.OutputStream

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        try {
            val resolver = context.contentResolver
            val contentValues = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, "secretFile.txt")
                put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
            val textUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)

            textUri?.let {
                val outputStream: OutputStream? = resolver.openOutputStream(it)
                outputStream?.use {
                    it.write("MAS_API_KEY=8767086b9f6f976g-a8df76\n".toByteArray())
                    it.flush()
                }
                Log.d("MediaStore", "File written to external storage successfully.")
                return  "SUCCESS!!\n\nMediaStore inserted to $textUri"
            } ?: run {
                Log.e("MediaStore", "Error inserting URI to MediaStore.")
                return  "FAILURE!!\n\nMediaStore couldn't insert data."
            }
        } catch (exception: Exception) {
            Log.e("MediaStore", "Error writing file to URI from MediaStore", exception)
            return "FAILURE!!\n\nMediaStore couldn't insert data."
        }
    }
}
