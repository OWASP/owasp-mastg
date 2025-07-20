package org.owasp.mastestapp

import android.content.Context
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class MastgTest(private val context: Context) {
    private val awsKey = "AKIAIOSFODNN7EXAMPLE"
    private val githubToken = "ghp_1234567890abcdefghijklmnOPQRSTUV"
    private val preSharedKeys = setOf(
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfX7kbfFv3pc3JjOHQ=",
        "gJXS9EwpuzK8U1TOgfplwfKEVngCE2D5FNBQWvNmuHHbigmTCabsA="
    )
    private val sharedPrefsName = "MasSharedPref_Sensitive_Data"

    fun mastgTest(): String {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            val encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                sharedPrefsName,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            encryptedPrefs.edit {
                putString("EncryptedAWSKey", awsKey)
                putString("GitHubToken", githubToken)
                putStringSet("preSharedKeys", preSharedKeys)
            }

            "Sensitive data has been written and deleted in the sandbox."
        } catch (e: Exception) {
            "Error during MastgTest: ${e.message ?: "Unknown error"}"
        }
    }
}
