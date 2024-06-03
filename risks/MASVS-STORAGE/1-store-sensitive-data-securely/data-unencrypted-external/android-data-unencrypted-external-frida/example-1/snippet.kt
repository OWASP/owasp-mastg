package org.owasp.mastestapp

import android.content.Context
import android.os.Environment
import android.os.Environment.getExternalStoragePublicDirectory
import java.io.File
import java.io.FileOutputStream

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val secret1 = "{\"password\":\"12345\"}\n"
        val externalDirPath = getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val file1 = File("$externalDirPath/secrets.json")
        FileOutputStream(file1).use { fos ->
            fos.write(secret1.toByteArray())
        }

        return "Secrets written to $file1:\n\n$secret1"
    }

}
