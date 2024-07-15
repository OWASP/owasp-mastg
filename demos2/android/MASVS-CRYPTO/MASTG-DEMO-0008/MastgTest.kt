package org.owasp.mastestapp

import android.content.Context
import java.util.Calendar
import java.util.Date

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        // SUMMARY: This sample demonstrates different ways of creating non-random tokens in Java.

        // FAIL: [android-insecure-random-use] The app uses Date().time for generating authentication tokens.
        val random1 = Date().time.toInt()

        val c = Calendar.getInstance()
        // FAIL: [android-insecure-random-use] The app uses Calendar.getInstance().timeInMillis for generating authentication tokens.
        val random2 = c.get(Calendar.MILLISECOND)

        return "Generated random numbers:\n$random1 \n$random2"
    }

}

