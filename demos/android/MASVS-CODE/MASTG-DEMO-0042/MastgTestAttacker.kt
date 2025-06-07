package com.example.intenttrigger

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val exploitButton: Button = findViewById(R.id.exploitButton)

        exploitButton.setOnClickListener {
            val exploitIntent = Intent()
            exploitIntent.action = "org.owasp.mastestapp.VULNERABLE_ACTION" // The vulnerable intent action
            exploitIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

            startActivity(exploitIntent) // Launch the vulnerable activity
        }
    }
}