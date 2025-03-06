package org.owasp.mastestapp

import android.content.Context

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val androidSdkVersion = getSystemSdkVersion()
        return "AndroidSdkVersion:$androidSdkVersion\n"
    }

    fun getSystemSdkVersion(): Int {
        return android.os.Build.VERSION.SDK_INT
    }
}
