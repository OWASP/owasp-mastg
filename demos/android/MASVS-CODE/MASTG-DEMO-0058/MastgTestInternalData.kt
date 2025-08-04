package org.owasp.mastestapp

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.TextView

class VulnerableActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Simple layout to show the received data
        val textView = TextView(this)
        textView.text = "Processing sensitive data..."
        setContentView(textView)

        // Process the received intent data
        val receivedData = StringBuilder("Received sensitive data:\n")

        intent?.let { intent ->
            intent.getStringExtra("sensitive_token")?.let {
                receivedData.append("Token: $it\n")
                Log.d("VULNERABLE-APP", "Received token: $it")
            }

            intent.getStringExtra("user_credentials")?.let {
                receivedData.append("Credentials: $it\n")
                Log.d("VULNERABLE-APP", "Received credentials: $it")
            }

            intent.getStringExtra("api_key")?.let {
                receivedData.append("API Key: $it\n")
                Log.d("VULNERABLE-APP", "Received API key: $it")
            }

            intent.getStringExtra("message")?.let {
                receivedData.append("Message: $it\n")
                Log.d("VULNERABLE-APP", "Received message: $it")
            }
        }

        textView.text = receivedData.toString()
        Log.d("VULNERABLE-APP", "VulnerableActivity processed data")
    }
}