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

    // Vulnerable AES encryption
    fun vulnerableAesEncryption(data: String): String {
        try {
            val key = "1234567890123456".toByteArray() // 16 bytes key for AES
            val secretKeySpec = SecretKeySpec(key, "AES")

            // Default mode for AES (ECB)
            val cipher = Cipher.getInstance("AES")
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Vulnerable AES with ECB and NoPadding (manual padding applied)
    fun vulnerableAesEcbNoPadding(data: String): String {
        try {
            val key = "1234567890123456".toByteArray()
            val secretKeySpec = SecretKeySpec(key, "AES")

            val cipher = Cipher.getInstance("AES/ECB/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)

            // Ensure the data is padded to match the block size
            val blockSize = 16
            val paddingLength = blockSize - (data.length % blockSize)
            val paddedData = data + "\u0000".repeat(paddingLength) // Null padding

            val encryptedData = cipher.doFinal(paddedData.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT).trim()
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Vulnerable AES with ECB and PKCS5Padding
    fun vulnerableAesEcbPkcs5Padding(data: String): String {
        try {
            val key = "1234567890123456".toByteArray()
            val secretKeySpec = SecretKeySpec(key, "AES")

            val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Vulnerable AES with ECB and ISO10126Padding
    fun vulnerableAesEcbIso10126Padding(data: String): String {
        try {
            val key = "1234567890123456".toByteArray()
            val secretKeySpec = SecretKeySpec(key, "AES")

            val cipher = Cipher.getInstance("AES/ECB/ISO10126Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Vulnerable DES with ECB and PKCS5Padding
    fun vulnerableDesEcbPkcs5Padding(data: String): String {
        try {
            val keySpec = DESKeySpec("12345678".toByteArray())
            val keyFactory = SecretKeyFactory.getInstance("DES")
            val secretKey: Key = keyFactory.generateSecret(keySpec)

            val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Vulnerable 3DES with ECB and PKCS5Padding
    fun vulnerable3DesEcbPkcs5Padding(data: String): String {
        try {
            val keySpec = DESedeKeySpec("123456789012345678901234".toByteArray())
            val keyFactory = SecretKeyFactory.getInstance("DESede")
            val secretKey: Key = keyFactory.generateSecret(keySpec)

            val cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val encryptedData = cipher.doFinal(data.toByteArray())
            return Base64.encodeToString(encryptedData, Base64.DEFAULT)
        } catch (e: Exception) {
            return "Encryption error: ${e.message}"
        }
    }

    // Test and return results
    fun mastgTest(): String {
        val sensitiveString = "Hello from OWASP MASTG!"

        val results = listOf(
            "AES Default: ${vulnerableAesEncryption(sensitiveString)}",
            "AES ECB NoPadding: ${vulnerableAesEcbNoPadding(sensitiveString)}",
            "AES ECB PKCS5Padding: ${vulnerableAesEcbPkcs5Padding(sensitiveString)}",
            "AES ECB ISO10126Padding: ${vulnerableAesEcbIso10126Padding(sensitiveString)}",
            "DES ECB PKCS5Padding: ${vulnerableDesEcbPkcs5Padding(sensitiveString)}",
            "3DES ECB PKCS5Padding: ${vulnerable3DesEcbPkcs5Padding(sensitiveString)}"
        )

        return results.joinToString("\n")
    }
}
