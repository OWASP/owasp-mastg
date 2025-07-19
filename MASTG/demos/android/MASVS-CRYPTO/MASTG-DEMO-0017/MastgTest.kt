package org.owasp.mastestapp

import android.content.Context
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

class MastgTest(private val context: Context) {

    fun mastgTest(): String {

        // Bad: Use of a hardcoded key (from bytes) for encryption
        val keyBytes = byteArrayOf(0x6C, 0x61, 0x6B, 0x64, 0x73, 0x6C, 0x6A, 0x6B, 0x61, 0x6C, 0x6B, 0x6A, 0x6C, 0x6B, 0x6C, 0x73) // Example key bytes
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(keyBytes, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        // Bad: Hardcoded key directly in code (security risk)
        val badSecretKeySpec = SecretKeySpec("my secret here".toByteArray(), "AES")


        // Returning results
        return "SUCCESS!!\n\nThe keys were generated and used successfully with the following details:\n\n" +
                "Hardcoded AES Encryption Key: ${Base64.encodeToString(keyBytes, Base64.DEFAULT)}\n" +
                "Hardcoded Key from string: ${Base64.encodeToString(badSecretKeySpec.encoded, Base64.DEFAULT)}\n"
    }
}
