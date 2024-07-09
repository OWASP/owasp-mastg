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
        mastgTestWriteIntFile()
        return "SUCCESS!!\n\nFile has been written to internal files dir"
    }
    
    fun mastgTestWriteIntFile() {
        val internalStorageDir = context.getFilesDir(null)
        val fileName = File(externalStorageDir, "secret.txt")
        val fileContent = "secr3tPa$$W0rd\n"

        try {
            FileOutputStream(fileName).use { output ->
                output.write(fileContent.toByteArray())
                Log.d("WriteInternalStorage", "File written to internal storage successfully.")
            }
        } catch (e: IOException) {
            Log.e("WriteInternalStorage", "Error writing file to internal storage", e)
        }
    }

}

