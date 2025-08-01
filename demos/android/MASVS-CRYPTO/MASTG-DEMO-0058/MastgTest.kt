package org.owasp.mastestapp

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import android.util.Base64
import javax.crypto.spec.SecretKeySpec

class MastgTest(private val context: Context) {

    fun mastgTest(): String {

        val results = mutableListOf<String>()
        var rawKey: SecretKey? = null
        var encryptedData: ByteArray? = null
        var decryptedData: ByteArray? = null

        // Suppose we received a raw key from a secure source and we want to use it for decryption.
        // The following commented-out code is an example of generating a raw key and encrypting data with it.
        // We obtained the raw key and encrypted data from the logs and added them to the code for demonstration purposes.
        try {
            // Suppose we received the raw key from a secure source and we want to use it for decryption.
            val rawKeyString = "43ede5660e82123ee091d6b4c8f7d150"
            val keyBytes = rawKeyString.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            rawKey = SecretKeySpec(keyBytes, KeyProperties.KEY_ALGORITHM_AES)

            // The cipher text is 'Hello from OWASP MASTG!' AES/ECB encrypted using CyberChef:
            // https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'43ede5660e82123ee091d6b4c8f7d150'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Hex',%7B'option':'Hex','string':''%7D)&input=SGVsbG8gZnJvbSBPV0FTUCBNQVNURyE
            val encryptedDataString = "20b0eef4e5ad3d8984a4fb94f6001885f0ce25104cb8251f600624b46dcefb92"
            encryptedData = encryptedDataString.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "importedAesKey"
            val entry = KeyStore.SecretKeyEntry(rawKey)
            val protection = KeyProtection.Builder(KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build()
            keyStore.setEntry(alias, entry, protection)
            val importedKey = keyStore.getKey(alias, null) as SecretKey
            val cipher2 = Cipher.getInstance("AES/ECB/PKCS7Padding").apply {
                init(Cipher.DECRYPT_MODE, importedKey)
            }
            decryptedData = cipher2.doFinal(encryptedData)
            val decryptedString = String(decryptedData)
            results.add("\n[*] Keystore-imported AES ECB key decryption (plaintext):\n\n$decryptedString")
        } catch (e: Exception) {
            results.add("\n[!] Keystore-imported AES ECB key decryption error:\n\n${e.message}")
        }

        // import the raw key into AndroidKeyStore for encryption which would fail unless randomized encryption is disabled (bad practice)
        try {
            if (rawKey == null || encryptedData == null) {
                throw IllegalStateException("Key or data missing for encryption")
            }
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "importedAesKey2"
            val entry = KeyStore.SecretKeyEntry(rawKey)
            val protection = KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setRandomizedEncryptionRequired(false) // For demonstration purposes, we disable randomized encryption
                .build()
            keyStore.setEntry(alias, entry, protection)
            val importedKey = keyStore.getKey(alias, null) as SecretKey
            val cipher3 = Cipher.getInstance("AES/ECB/PKCS7Padding").apply {
                init(Cipher.ENCRYPT_MODE, importedKey)
            }
            val encryptedBytes = cipher3.doFinal(decryptedData)
            val encrypted = Base64.encodeToString(encryptedBytes, Base64.DEFAULT)

            results.add("\n\n[*] Keystore-imported AES ECB key encryption (ciphertext):\n\n$encrypted")
        } catch (e: Exception) {
            results.add("\n\n[!] Keystore-imported AES ECB key encryption error:\n\n${e.message}")
        }

        // keystore key generation and encryption
        try {
            val keyAlias = "testKeyGenParameter"
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                // .setRandomizedEncryptionRequired(false) // Disabling randomized encryption would allow the key to be used in ECB mode.
                .build()
            KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            ).apply {
                init(spec)
                generateKey()
            }

            val secretKey = keyStore.getKey(keyAlias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/ECB/PKCS7Padding").apply {
                init(Cipher.ENCRYPT_MODE, secretKey)
            }
            val encrypted = Base64.encodeToString(cipher.doFinal(decryptedData), Base64.DEFAULT)
            results.add("\n[*] Keystore-generated AES ECB key encryption (ciphertext):\n\n$encrypted")
        } catch (e: Exception) {
            results.add("\n[!] Keystore-generated AES ECB error:\n\n${e.message}")
        }

        return results.joinToString("\n")
    }
}