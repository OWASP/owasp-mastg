package com.example

import android.content.Intent
import android.os.Bundle
import android.os.Environment
import android.os.Environment.getDownloadCacheDirectory
import android.os.Environment.getExternalStorageDirectory
import android.os.Environment.getExternalStoragePublicDirectory
import android.view.View
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_main)
        saveDatabase()
    }

    fun saveDatabase(){
        try {
            val externalDirPath = getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val file: File = File("$externalDirPath/download.json")
            FileOutputStream(file).use { fos ->
                fos.write("password:12345".toByteArray())
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }
}
