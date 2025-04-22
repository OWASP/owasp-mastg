package org.owasp.mastestapp

import android.content.Context
import android.util.Log
import org.json.JSONObject
import org.json.JSONArray
import java.io.File

class MastgTest(private val context: Context) {

    private val sensitiveData = mapOf(
        "username" to "admin",
        "password" to "SuperSecret123!",
        "api_key" to "AKIAIOSFODNN7EXAMPLE",
        "auth_token" to "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    )

    // Vulnerable function: stores sensitive data in an insecure JSON file
    fun storeSensitiveDataInsecurely(): Boolean {
        try {
            val jsonData = JSONObject(sensitiveData as Map<*, *>)
            val file = File(context.filesDir, "config.json")
            file.writeText(jsonData.toString())
            Log.d("MASTG-TEST", "Sensitive data stored insecurely at: ${file.absolutePath}")
            return true
        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Error storing data", e)
            return false
        }
    }

    // Vulnerable function: loads sensitive data without proper validation
    fun loadSensitiveDataInsecurely(): Map<String, String> {
        try {
            val file = File(context.filesDir, "config.json")
            val jsonString = file.readText()
            val jsonData = JSONObject(jsonString)

            val result = mutableMapOf<String, String>()
            val keys = jsonData.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                result[key] = jsonData.getString(key)
            }

            Log.d("MASTG-TEST", "Loaded sensitive data: $result")
            return result
        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Error loading data", e)
            return emptyMap()
        }
    }

    // Another vulnerable example: storing serialized JSON array with sensitive data
    fun storeSensitiveArrayInsecurely(): Boolean {
        try {
            val jsonArray = JSONArray()
            jsonArray.put(JSONObject(mapOf("credit_card" to "4111111111111111", "cvv" to "123")))
            jsonArray.put(JSONObject(mapOf("credit_card" to "5555555555554444", "cvv" to "456")))

            val file = File(context.filesDir, "transactions.json")
            file.writeText(jsonArray.toString())
            Log.d("MASTG-TEST", "Sensitive array stored insecurely at: ${file.absolutePath}")
            return true
        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Error storing array", e)
            return false
        }
    }

    fun mastgTest(): String {
        // Store sensitive data
        storeSensitiveDataInsecurely()
        
        // Load sensitive data
        val loadedData = loadSensitiveDataInsecurely()
        
        // Store sensitive array
        storeSensitiveArrayInsecurely()
        
        return "MASTG Test completed successfully. Check logs for details."
    }
}