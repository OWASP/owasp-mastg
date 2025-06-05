package org.owasp.mastestapp

import android.content.Context
import android.content.SharedPreferences
import android.util.Log

class MastgTest(private val context: Context) {
    private val sharedPref: SharedPreferences =
        context.getSharedPreferences("VulnerablePrefs", Context.MODE_PRIVATE)

    // Store initial data
    fun storeInitialData(): String {
        try {
            sharedPref.edit().apply {
                putInt("userLevel", 1)
                putBoolean("isAdmin", false)
                putString("userData", """{"name":"user","admin":false}""")
                putString("htmlContent", "Welcome <b>user</b>")
                putStringSet("permissions", setOf("read", "basic_write"))
                apply()
            }
            return "Initial data stored successfully"
        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Storage error: ${e.message}")
            return "Error storing data: ${e.message}"
        }
    }

    // Read potentially tampered data
    fun readTamperedData(): String {
        return try {
            """
            TAMPERED DATA:
            --------------------------
            USER LEVEL: ${sharedPref.getInt("userLevel", 0)}
            IS ADMIN: ${sharedPref.getBoolean("isAdmin", false)}
            
            USER JSON: ${sharedPref.getString("userData", "DEFAULT")}
            HTML CONTENT: ${sharedPref.getString("htmlContent", "DEFAULT")}
            
            PERMISSIONS: ${sharedPref.getStringSet("permissions", setOf("DEFAULT"))}
            --------------------------
            """.trimIndent()
        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Read error: ${e.message}")
            "Error reading tampered data: ${e.message}"
        }
    }

    fun mastgTest(): String {
        // Store initial data
        val storeResult = try {
            sharedPref.edit().apply {
                putInt("userLevel", 1)
                putBoolean("isAdmin", false)
                putString("userData", """{"name":"user","admin":false}""")
                putString("htmlContent", "Welcome <b>user</b>")
                putStringSet("permissions", setOf("read", "basic_write"))
                apply()
            }
            "Initial data stored successfully"
        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Storage error: ${e.message}")
            "Error storing data: ${e.message}"
        }

        // Read potentially tampered data
        val readResult = try {
            """
            TAMPERED DATA:
            --------------------------
            USER LEVEL: ${sharedPref.getInt("userLevel", 0)}
            IS ADMIN: ${sharedPref.getBoolean("isAdmin", false)}
            
            USER JSON: ${sharedPref.getString("userData", "DEFAULT")}
            HTML CONTENT: ${sharedPref.getString("htmlContent", "DEFAULT")}
            
            PERMISSIONS: ${sharedPref.getStringSet("permissions", setOf("DEFAULT"))}
            --------------------------
            """.trimIndent()
        } catch (e: Exception) {
            Log.e("MASTG-TEST", "Read error: ${e.message}")
            "Error reading tampered data: ${e.message}"
        }

        return "$storeResult\n\n$readResult"
    }
}