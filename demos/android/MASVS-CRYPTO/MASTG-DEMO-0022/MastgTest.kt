package org.owasp.mastestapp

import android.content.Context
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.DESedeKeySpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import java.security.SecureRandom
import javax.crypto.SecretKey

class MastgTest(private val context: Context) {

    // Vulnerable encryption using DES (broken algorithm)
    fun vulnerableDesEncryption(data: String): String {
        try {
            // insufficient key for DES
            val keyBytes = ByteArray(8)
            SecureRandom().nextBytes(keyBytes)
            val keySpec = DESKeySpec(keyBytes)
            val keyFactory = SecretKeyFactory.getInstance("DES")
            val secretKey: Key = keyFactory.generateSecret(keySpec)

            // Risky encryption algorithm (DES)
            val cipher = Cipher.getInstance("DES")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }


    // Vulnerable encryption using 3DES (Triple DES)
    fun vulnerable3DesEncryption(data: String): String {
        try {
            val keyBytes = ByteArray(24)
            SecureRandom().nextBytes(keyBytes)
            val keySpec = DESedeKeySpec(keyBytes)
            val keyFactory = SecretKeyFactory.getInstance("DESede")
            val secretKey: Key = keyFactory.generateSecret(keySpec)

            // Risky encryption algorithm (3DES)
            val cipher = Cipher.getInstance("DESede")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Insecure encryption using RC4 (ARCFOUR) (Deprecated)
    fun vulnerableRc4Encryption(data: String): String {
        return try {
            val keyBytes = ByteArray(16)
            SecureRandom().nextBytes(keyBytes)
            val secretKey = SecretKeySpec(keyBytes, "RC4")

            val cipher = Cipher.getInstance("RC4")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val encryptedData = cipher.doFinal(data.toByteArray())
            Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            "Encryption error: ${e.message}"
        }
    }

    // Risky encryption using Blowfish (weak algorithm)
    fun vulnerableBlowfishEncryption(data: String): String {
        return try {
            // insufficient key for Blowfish (risky, small key size)
            val keyBytes = ByteArray(8) // Only 8 bytes (64-bit key) - not secure
            SecureRandom().nextBytes(keyBytes)
            val secretKey: SecretKey = SecretKeySpec(keyBytes, "Blowfish")

            // Risky encryption algorithm (Blowfish)
            val cipher = Cipher.getInstance("Blowfish")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val encryptedData = cipher.doFinal(data.toByteArray())
            Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            "Encryption error: ${e.message}"
        }
    }


    fun mastgTest(): String {
        val sensitiveString = "Hello from the OWASP MASTG Test app."

        // Encrypt with broken DES
        val desEncryptedString = vulnerableDesEncryption(sensitiveString)

        // Encrypt with risky 3DES
        val tripleDesEncryptedString = vulnerable3DesEncryption(sensitiveString)

        // Encrypt with deprecated RC4
        val rc4EncryptedString = vulnerableRc4Encryption(sensitiveString)

        // Encrypt with risky Blowfish
        val blowfishEncryptedString = vulnerableBlowfishEncryption(sensitiveString)

        // Returning the encrypted results
        return "DES Encrypted: $desEncryptedString\n3DES Encrypted: $tripleDesEncryptedString\nRC4 Encrypted: $rc4EncryptedString\nBlowfish Encrypted: $blowfishEncryptedString"
    }
}