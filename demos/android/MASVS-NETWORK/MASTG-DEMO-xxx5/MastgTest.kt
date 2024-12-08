package org.owasp.mastestapp

import android.content.Context

import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URL
import javax.net.ssl.*

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        var sensitiveString = "Hello from the OWASP MASTG Test app."

        runBlocking {
            withContext(Dispatchers.IO) {
                try {
                    // Create a TrustManager that ignores certificate validation
                    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
                    })

                    // Set up the SSLContext with the custom TrustManager
                    val sslContext = SSLContext.getInstance("TLS")
                    sslContext.init(null, trustAllCerts, java.security.SecureRandom())

                    // Use the custom SSLSocketFactory for connections
                    val url = URL("https://self-signed.badssl.com/")
                    val connection = url.openConnection() as HttpsURLConnection
                    connection.sslSocketFactory = sslContext.socketFactory

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
