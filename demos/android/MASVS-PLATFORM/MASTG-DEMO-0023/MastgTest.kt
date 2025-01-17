package org.owasp.mastestapp

import android.util.Log
import android.content.Context

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val sensitiveString = "Hello from the OWASP MASTG Test app."

        Log.d("MASTG-TEST", sensitiveString)
        return sensitiveString
    }

}