package org.owasp.mastestapp

import android.app.KeyguardManager
import android.content.Context
import android.os.Build


class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val isLocked = isDeviceSecure(context)
        val androidSdkVersion = getSystemSdkVersion()
        val isSystemDebuggable = isSystemDebuggable()
        return "Device has a passcode: $isLocked\nandroidSdkVersion:$androidSdkVersion\nisSystemDebuggable:$isSystemDebuggable"
    }

    fun isDeviceSecure(context: Context): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return keyguardManager.isDeviceSecure
    }

    fun getSystemSdkVersion(): Int {
        return android.os.Build.VERSION.SDK_INT
    }

    fun isSystemDebuggable(): Boolean {
        return Build.TYPE == "eng" || Build.TYPE == "userdebug"
    }
}
