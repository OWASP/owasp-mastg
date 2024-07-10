package org.owasp.mastestapp

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        mastgTestWriteIntFile()
        return "SUCCESS!!\n\nFile has been written to internal files dir"
    }

    private fun mastgTestWriteIntFile() {
        val internalStorageDir = context.filesDir
        val fileName = File(internalStorageDir, "secret.txt")
        val fileContent = "secr3tPa\$\$W0rd\n"

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

