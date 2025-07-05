package org.owasp.mastestapp

import android.util.Log
import android.content.Context
import android.content.Intent

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val sensitiveString = "Hello from the OWASP MASTG Test app."

        // Vulnerable: Using implicit intent with sensitive data
        val vulnerableIntent = Intent().apply {
            action = "org.owasp.mastestapp.PROCESS_SENSITIVE_DATA"
            putExtra("sensitive_token", "auth_token_12345")
            putExtra("user_credentials", "admin:password123")
            putExtra("api_key", "sk-1234567890abcdef")
            putExtra("message", sensitiveString)
        }

        // Launch implicit intent - any app can intercept this
        try {
            context.startActivity(vulnerableIntent)
            Log.d("MASTG-TEST", "Launched vulnerable implicit intent with sensitive data")
        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Failed to launch intent: ${e.message}")
        }

        Log.d("MASTG-TEST", sensitiveString)
        return sensitiveString
    }
}