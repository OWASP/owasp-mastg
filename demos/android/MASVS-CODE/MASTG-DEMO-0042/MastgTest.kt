package org.owasp.mastestapp

import android.content.Context
import android.content.Intent
import android.util.Log

class MastgTest(private val context: Context) {

    fun mastgTest(): String {
        val sensitiveString = "Hello from the OWASP MASTG Test app. Try to send intent."
        Log.d("MASTG-TEST", sensitiveString)
        return sensitiveString
    }

    fun triggerVulnerableIntent() {
        val intent = Intent()
        intent.action = "org.owasp.mastestapp.VULNERABLE_ACTION"
        context.startActivity(intent)  // Vulnerable: Starting activity with implicit intent
    }
}
