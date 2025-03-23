package org.owasp.mastestapp

import android.app.AlertDialog
import android.content.Context
import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        showPopup(context)
        return "The popup contains some caching input fields"
    }

    fun showPopup(context: Context) {
        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(50, 20, 50, 20)
        }

        val input1 = EditText(context).apply {
            hint = "Enter password (not cached)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        val input2 = EditText(context).apply {
            hint = "Enter password (cached)"
            inputType = InputType.TYPE_CLASS_TEXT
        }

        val input3 = EditText(context).apply {
            hint = "Enter PIN (cached)"
            inputType =  InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        }

        input3.inputType = InputType.TYPE_CLASS_NUMBER

        layout.addView(input1)
        layout.addView(input2)
        layout.addView(input3)

        AlertDialog.Builder(context)
            .setTitle("Sign Up Form")
            .setView(layout)
            .setPositiveButton("Sign Up") { _, _ -> }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
