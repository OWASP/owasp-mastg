package org.owasp.mastestapp

import android.content.Context
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.DESedeKeySpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

class MastgTest(private val context: Context) {

    // Vulnerable encryption using DES (weak algorithm)
    fun vulnerableDesEncryption(data: String): String {
        try {
            // Weak key for DES
            val keySpec = DESKeySpec("12345678".toByteArray())
            val keyFactory = SecretKeyFactory.getInstance("DES")
            val secretKey: Key = keyFactory.generateSecret(keySpec)

            // Weak encryption algorithm (DES) and weak mode (ECB)
            val cipher = Cipher.getInstance("DES")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Vulnerable AES with ECB mode
    fun vulnerableAesEcbEncryption(data: String): String {
        try {
            // Weak AES key (only for demonstration)
            val key = "1234567890123456".toByteArray() // 16 bytes key for AES

            // Using AES with ECB (default mode)
            val secretKeySpec = SecretKeySpec(key, "AES")
            val cipher = Cipher.getInstance("AES")
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Vulnerable encryption using 3DES (Triple DES)
    fun vulnerable3DesEncryption(data: String): String {
        try {
            // Weak key for 3DES (24-byte key)
            val keySpec = DESedeKeySpec("123456789012345678901234".toByteArray()) // 24 bytes key
            val keyFactory = SecretKeyFactory.getInstance("DESede")
            val secretKey: Key = keyFactory.generateSecret(keySpec)

            // Weak encryption algorithm (3DES)
            val cipher = Cipher.getInstance("DESede")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    fun mastgTest(): String {
        val sensitiveString = "Hello from the OWASP MASTG Test app."

        // Encrypt with weak DES
        val desEncryptedString = vulnerableDesEncryption(sensitiveString)

        // Encrypt with weak AES in ECB mode
        val aesEcbEncryptedString = vulnerableAesEcbEncryption(sensitiveString)

        // Encrypt with weak 3DES
        val tripleDesEncryptedString = vulnerable3DesEncryption(sensitiveString)

        // Returning the encrypted results
        return "DES Encrypted: $desEncryptedString\nAES ECB Encrypted: $aesEcbEncryptedString\n3DES Encrypted: $tripleDesEncryptedString"
    }
}
