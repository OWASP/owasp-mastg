package org.owasp.mastestapp

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.core.content.edit
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * This is the main test class that orchestrates the demonstration.
 * It now contains all logic in a single class to simplify decompilation.
 * It uses a two-step process to allow for manual tampering.
 */
class MastgTest(private val context: Context) {

    companion object {
        private const val PREFS_NAME = "app_settings"
        private const val HMAC_ALGORITHM = "HmacSHA256"
        // WARNING: In a real application, this key should NOT be hardcoded.
        // It should be stored securely, for instance, in the Android Keystore.
        // For this self-contained demo, we hardcode it to illustrate the HMAC mechanism.
        private const val SECRET_KEY = "this-is-a-very-secret-key-for-the-demo"
    }

    /**
     * Main test function that runs the setup or verification phase.
     */
    fun mastgTest(): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Check if the initial setup has been performed.
        if (!prefs.contains("setup_complete")) {
            // --- FIRST-TIME EXECUTION: SETUP PHASE ---
            // This block runs only once.

            // 1. Set up the insecure preference (without HMAC).
            saveData("user_role_insecure", "user", useHmac = false)

            // 2. Set up the secure preference (with HMAC).
            saveData("user_role_secure", "user", useHmac = true)

            // 3. Mark setup as complete so this block doesn't run again.
            prefs.edit(commit = true) {
                putBoolean("setup_complete", true)
            }

            // 4. Return instructions for the user.
            return "INITIAL SETUP COMPLETE.\n\n" +
                    "The role for both secure and insecure tests has been set to 'user'.\n\n" +
                    "ACTION REQUIRED:\n" +
                    "1. Use a file explorer or ADB shell on a rooted device.\n" +
                    "2. Go to: /data/data/org.owasp.mastestapp/shared_prefs/\n" +
                    "3. Open the file: app_settings.xml\n" +
                    "4. Change BOTH <string>user</string> values to <string>admin</string>.\n" +
                    "5. Save the file and run this test again to see the results."

        } else {
            // --- SUBSEQUENT EXECUTION: VERIFICATION PHASE ---
            // This block runs after the user has tampered with the file.

            val results = StringBuilder()

            // 1. Verify the 'fail' case (insecure)
            results.append("--- VERIFYING SCENARIO 1: 'kind: fail' (No HMAC Protection) ---\n")
            val insecureRole = loadData("user_role_insecure", "error", useHmac = false)
            results.append("Loaded role from 'user_role_insecure': '$insecureRole'\n")
            if (insecureRole == "admin") {
                results.append(">> OUTCOME: VULNERABLE. The application accepted the tampered 'admin' role because there was no integrity check.\n")
            } else {
                results.append(">> OUTCOME: NOT EXPLOITED. The role is still '$insecureRole'. Please ensure you changed it to 'admin' in the XML file.\n")
            }

            // 2. Verify the 'pass' case (secure)
            results.append("\n--- VERIFYING SCENARIO 2: 'kind: pass' (HMAC Protection Enabled) ---\n")
            val secureRole = loadData("user_role_secure", "tampering_detected", useHmac = true)
            results.append("Loaded role from 'user_role_secure': '$secureRole'\n")
            if (secureRole == "tampering_detected") {
                results.append(">> OUTCOME: SECURE. The application detected that the data was tampered with and correctly rejected the invalid 'admin' role.\n")
            } else if (secureRole == "admin") {
                results.append(">> OUTCOME: UNEXPECTED. The role is 'admin', which means the HMAC check failed. This should not happen.\n")
            } else { // secureRole == "user"
                results.append(">> OUTCOME: NOT TAMPERED. The role is still '$secureRole', and its HMAC signature is valid.\n")
            }

            results.append("\n\nTest complete. To run the setup again, please clear the application's data in Android Settings and restart the test.")
            return results.toString()
        }
    }

    /**
     * Saves a key-value pair. If HMAC is enabled, it also saves an integrity check value.
     */
    private fun saveData(key: String, value: String, useHmac: Boolean) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit(commit = true) {
            putString(key, value)
            if (useHmac) {
                val hmac = calculateHmac(value)
                if (hmac != null) {
                    putString("${key}_hmac", hmac)
                    Log.d("MASTG-TEST", "Saved data with HMAC.")
                }
            } else {
                Log.d("MASTG-TEST", "Saved data WITHOUT HMAC.")
            }
        }
    }

    /**
     * Loads data for a given key. If HMAC is enabled, it first verifies the data's integrity.
     */
    private fun loadData(key: String, defaultValue: String, useHmac: Boolean): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val value = prefs.getString(key, null) ?: return defaultValue

        if (!useHmac) {
            Log.d("MASTG-TEST", "Loaded data without HMAC check. Value is: $value")
            return value
        }

        val storedHmac = prefs.getString("${key}_hmac", null)
        if (storedHmac == null) {
            Log.w("MASTG-TEST", "HMAC verification failed: No HMAC found for key '$key'.")
            return defaultValue
        }

        val calculatedHmac = calculateHmac(value)

        return if (storedHmac == calculatedHmac) {
            Log.d("MASTG-TEST", "HMAC verification SUCCESS. Value is: $value")
            value
        } else {
            Log.e("MASTG-TEST", "HMAC verification FAILED! Data has been tampered with.")
            defaultValue
        }
    }

    /**
     * Calculates the HMAC for a given piece of data.
     */
    private fun calculateHmac(data: String): String? {
        return try {
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            val secretKeySpec = SecretKeySpec(SECRET_KEY.toByteArray(), HMAC_ALGORITHM)
            mac.init(secretKeySpec)
            val hmacBytes = mac.doFinal(data.toByteArray())
            bytesToHex(hmacBytes)
        } catch (e: NoSuchAlgorithmException) {
            Log.e("MASTG-TEST", "HMAC algorithm not found", e)
            null
        } catch (e: InvalidKeyException) {
            Log.e("MASTG-TEST", "Invalid HMAC key", e)
            null
        }
    }

    /**
     * Helper function to convert a byte array to a hexadecimal string.
     */
    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = "0123456789abcdef"
        val result = StringBuilder(bytes.size * 2)
        bytes.forEach {
            val i = it.toInt()
            result.append(hexChars[i shr 4 and 0x0f])
            result.append(hexChars[i and 0x0f])
        }
        return result.toString()
    }
}
