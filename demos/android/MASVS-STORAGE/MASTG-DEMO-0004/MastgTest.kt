package org.owasp.mastestapp

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

class MastgTest (private val context: Context){

    fun mastgTest(): String {

        val externalStorageDir = context.getExternalFilesDir(null)

        val fileName = File(externalStorageDir, "secret.txt")
        val fileContent = "secr3tPa\$\$W0rd\n"

        try {
            FileOutputStream(fileName).use { output ->
                output.write(fileContent.toByteArray())
                Log.d("WriteExternalStorage", "File written to external storage successfully.")
            }
        } catch (e: IOException) {
            Log.e("WriteExternalStorage", "Error writing file to external storage", e)
            return "ERROR!!\n\nError writing file to external storage"
        }

        return "SUCCESS!!\n\nFile $fileName with content $fileContent saved to $externalStorageDir"
    }
}
