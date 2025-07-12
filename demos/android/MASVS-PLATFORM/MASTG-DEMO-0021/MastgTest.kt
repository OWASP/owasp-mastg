package org.owasp.mastestapp

import android.app.Activity
import android.content.Context
import android.view.WindowManager.LayoutParams

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        if (context is Activity) {
            context.window.setFlags(
                LayoutParams.FLAG_SECURE,
                LayoutParams.FLAG_SECURE
            )
            return "SUCCESS!!\n\nThe FLAG_SECURE has been set"
        } else {
            return "ERROR: Context is not an Activity"
        }
    }
}
