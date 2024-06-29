package org.owasp.mastestapp

import android.content.Context
import android.os.Environment
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

class MastgTest (private val context: Context){

    fun mastgTest(): String {

        val externalStorageDir = Environment.getExternalStorageDirectory()

        val fileName = File(externalStorageDir, "secret.txt")
        val fileContent = "Secret not using scoped storage"

        try {
            FileOutputStream(fileName).use { output ->
                output.write(fileContent.toByteArray())
                Log.d("WriteExternalStorage", "File written to external storage successfully.")
            }
        } catch (e: IOException) {
            Log.e("WriteExternalStorage", "Error writing file to external storage", e)
            return "ERROR!!\n\nError writing file to external storage. Do you have the MANAGE_EXTERNAL_STORAGE permission in the manifest and it's granted in 'All files access'?"
        }

        return "SUCCESS!!\n\nFile $fileName with content $fileContent saved to $externalStorageDir"
    }
}
