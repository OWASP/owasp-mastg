package org.owasp.mastestapp

import android.content.Context

import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        var result = ""

        runBlocking {
            withContext(Dispatchers.IO) {
                try {
                    // Create a URL connection
                    val url = URL("https://self-signed.badssl.com/")
                    val connection = url.openConnection() as HttpURLConnection

                    // Perform the request
                    connection.connect()
                    val responseCode = connection.responseCode

                    if (responseCode == 200) {
                        // Read the response
                        val reader = BufferedReader(InputStreamReader(connection.inputStream))
                        val response = reader.readText()
                        result = "Connection Successful: ${response.substring(0, minOf(200, response.length))}"
                    } else {
                        result = "Connection Failed with code: $responseCode"
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    result = "Connection Failed: ${e::class.simpleName} - ${e.message}"
                }
            }
        }

        return result
    }

}
