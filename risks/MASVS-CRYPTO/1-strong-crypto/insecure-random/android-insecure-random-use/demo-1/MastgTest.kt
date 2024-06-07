package org.owasp.mastestapp

import android.content.Context
import java.util.Random
import java.lang.*
import java.security.SecureRandom

class MastgTest (private val context: Context){

    fun mastgTest(): String {

        // FAIL: [android-insecure-random-use] The app insecurely uses random numbers for generating authentication tokens.
        val random1 = Random().nextDouble()

        // FAIL: [android-insecure-random-use] The title of the function indicates that it generates a random number, but it is unclear how it is actually used in the rest of the app. Review any calls to this function to ensure that the random number is not used in a security-relevant context.
        val random2 = 1 + Math.random()

        val length = 16
        val characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val random = Random()
        val password = StringBuilder(length)

        for (i in 0 until length) {
            // FAIL: [android-insecure-random-use] The app insecurely uses random numbers for generating passwords, which is a security-relevant context.
            password.append(characters[random.nextInt(characters.length)])
        }

        val random3 = password.toString()

        // PASS: [android-insecure-random-use] The app uses a secure random number generator.

        val random4 = SecureRandom().nextInt(21)

        return "Generated random numbers:\n$random1 \n$random2 \n$random3 \n$random4"
    }

}
