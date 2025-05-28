package org.owasp.mastestapp

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

class VulnerableActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val textView = TextView(this)
        textView.text = "FLAG{IMPLICIT_INTENT_VULNERABILITY}"
        textView.textSize = 20f

        setContentView(textView)
    }
}
