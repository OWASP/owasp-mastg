package org.owasp.mastestapp

import android.util.Log
import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader

class MastgTest(private val context: Context) {

    companion object {
        private const val TAG = "RootCheck"
    }

    fun mastgTest(): String {
        return when {
            checkRootFiles() || checkSuperUserApk() || checkSuCommand() || checkDangerousProperties() -> {
                "Device is rooted"
            }
            else -> {
                "Device is not rooted"
            }
        }
    }

    private fun checkRootFiles(): Boolean {
        val rootPaths = setOf(
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/sd/xbin/su",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu"
        )
        rootPaths.forEach { path ->
            if (File(path).exists()) {
                Log.d(TAG, "Found root file: $path")
            }
        }
        return rootPaths.any { path -> File(path).exists() }
    }

    private fun checkSuperUserApk(): Boolean {
        val superUserApk = File("/system/app/Superuser.apk")
        val exists = superUserApk.exists()
        if (exists) {
            Log.d(TAG, "Found Superuser.apk")
        }
        return exists
    }

    private fun checkSuCommand(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            if (result != null) {
                Log.d(TAG, "su command found at: $result")
                true
            } else {
                Log.d(TAG, "su command not found")
                false
            }
        } catch (e: IOException) {
            Log.e(TAG, "Error checking su command: ${e.message}", e)
            false
        }
    }

    private fun checkDangerousProperties(): Boolean {
        val dangerousProps = arrayOf("ro.debuggable", "ro.secure", "ro.build.tags")
        dangerousProps.forEach { prop ->
            val value = getSystemProperty(prop)
            if (value != null) {
                Log.d(TAG, "Dangerous property $prop: $value")
                if (value.contains("debug")) {
                    return true
                }
            }
        }
        return false
    }

    private fun getSystemProperty(prop: String): String? {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", prop))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            reader.readLine()
        } catch (e: IOException) {
            Log.e(TAG, "Error checking system property $prop: ${e.message}", e)
            null
        }
    }
}
