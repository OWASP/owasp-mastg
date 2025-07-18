package com.example.datainteceptor

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val textView = TextView(this)
        textView.text = "Exploit App Ready. Waiting to intercept intent..."
        setContentView(textView)
    }
}
