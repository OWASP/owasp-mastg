package org.owasp.mastestapp

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

class MastgTest (private val context: Context){

    fun mastgTest(): String {
//        val r = DemoResults("0058")

        try {
            val b = KeyGenParameterSpec.Builder(
                "testKeyGenParameter",
                KeyProperties.PURPOSE_ENCRYPT
            )
            b.setBlockModes(KeyProperties.BLOCK_MODE_ECB)
//            r.add(Status.FAIL, "The associated key can only use the insecure symmetric encryption block mode ECB.")

            b.setBlockModes(KeyProperties.BLOCK_MODE_ECB, KeyProperties.BLOCK_MODE_CBC)
//            r.add(Status.FAIL, "The associated key may use the insecure symmetric encryption block mode ECB.")

            b.setBlockModes(KeyProperties.BLOCK_MODE_CBC, KeyProperties.BLOCK_MODE_ECB)
//            r.add(Status.FAIL, "The associated key may use the insecure symmetric encryption block mode ECB.")

        }
        catch (e: Exception){
//            r.add(Status.ERROR, e.toString())
        }
//        return r.toJson()\
        return "The associated key can use the insecure symmetric encryption block mode ECB."
    }

}
