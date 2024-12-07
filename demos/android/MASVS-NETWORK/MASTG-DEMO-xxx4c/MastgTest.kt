package org.owasp.mastestapp

import android.content.Context
import android.webkit.WebView

import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class MastgTest (private val context: Context){

    fun mastgTest(webView: WebView? = null): String {
        var sensitiveString = "Hello from the OWASP MASTG Test app."

        runBlocking {
            withContext(Dispatchers.IO) {
                try {
                    // Create a URL connection
                    val url = URL("http://http.badssl.com/")
                    val connection = url.openConnection() as HttpURLConnection

                    // Perform the request
                    connection.connect()
                    val responseCode = connection.responseCode

                    if (responseCode == 200) {
                        // Read the response
                        val reader = BufferedReader(InputStreamReader(connection.inputStream))
                        val response = reader.readText()
                        sensitiveString = "Connection Successful: ${response.substring(0, minOf(200, response.length))}"
                    } else {
                        sensitiveString = "Connection Failed with code: $responseCode"
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    sensitiveString = "Connection Failed: ${e::class.simpleName} - ${e.message}"
                }
            }
        }

        return sensitiveString
    }

}
