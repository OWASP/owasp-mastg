package org.owasp.mastestapp

import android.util.Log
import android.content.Context
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class MastgTest (private val context: Context){

    fun mastgTest(): String {

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
        generator.initialize(1024, SecureRandom())
        val keypair = generator.genKeyPair()
        Log.d("Keypair generated RSA", Base64.encodeToString(keypair.public.encoded, Base64.DEFAULT))

        val keyGen1 = KeyGenerator.getInstance("AES")
        keyGen1.init(128)
        val secretKey1: SecretKey = keyGen1.generateKey()

        val keyGen2 = KeyGenerator.getInstance("AES")
        keyGen2.init(256)
        val secretKey2: SecretKey = keyGen2.generateKey()

        return "Generated RSA Key:\n " + Base64.encodeToString(keypair.public.encoded, Base64.DEFAULT)+"Generated AES Key1\n "+ Base64.encodeToString(secretKey1.encoded, Base64.DEFAULT)+ "Generated AES Key2\n "+ Base64.encodeToString(secretKey2.encoded, Base64.DEFAULT);

    }

}
