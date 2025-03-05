package org.owasp.mastestapp

import android.app.AlertDialog
import android.app.KeyguardManager
import android.content.Context
import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        showPopup(context)
        return "The popup contains caching input fields"
    }

    fun showPopup(context: Context) {
        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(50, 20, 50, 20)
        }

        val input1 = EditText(context).apply {
            hint = "Enter password"
            inputType = InputType.TYPE_TEXT_VARIATION_PHONETIC
        }
        val input2 = EditText(context).apply {
            hint = "Enter passcode"
            inputType = InputType.TYPE_CLASS_NUMBER
        }

        layout.addView(input1)
        layout.addView(input2)

        AlertDialog.Builder(context)
            .setTitle("Sign Up Form")
            .setView(layout)
            .setPositiveButton("Sign Up") { _, _ -> }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
