package org.owasp.mastestapp

import android.content.Context
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory

class MastgTest(private val context: Context) {

    fun mastgTest(): String {
        var result = ""

        runBlocking {
            withContext(Dispatchers.IO) {
                try {
                    // Create a URL connection
                    val url = URL("https://tls-v1-2.badssl.com:1012/")
                    val connection = (url.openConnection() as HttpURLConnection).apply {
                        if (this is javax.net.ssl.HttpsURLConnection) {
                            sslSocketFactory = createTls12SocketFactory()
                        }
                    }

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

    private fun createTls12SocketFactory(): SSLSocketFactory {
        val sslContext = SSLContext.getInstance("TLSv1.2")
        sslContext.init(null, null, java.security.SecureRandom()) // Use the default TrustManager
        return sslContext.socketFactory
    }
}
