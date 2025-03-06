package org.owasp.mastestapp

import android.app.KeyguardManager
import android.content.Context
import android.os.Build


class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val isLocked = isDeviceSecure(context)
        if(isLocked){
            return "Device has a passcode"    
        }
        else{
            return "Device doesn't have a passcode"
        }
    }

    fun isDeviceSecure(context: Context): Boolean {
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return keyguardManager.isDeviceSecure
    }

    fun getSystemSdkVersion(): Int {
        return android.os.Build.VERSION.SDK_INT
    }
}
