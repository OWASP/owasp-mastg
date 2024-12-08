package org.owasp.mastestapp

import android.util.Log
import android.content.Context

import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import javax.net.ssl.*

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        var sensitiveString = "Hello from the OWASP MASTG Test app."

        // Launch the network operation in a coroutine
        runBlocking {
            withContext(Dispatchers.IO) {
                try {
                    // Enable SSL debugging for detailed logs (optional)
                    System.setProperty("javax.net.debug", "ssl,handshake")

                    // Create a custom TrustManager that ignores certificate validation
                    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {
                            // No validation needed
                        }

                        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {
                            // No validation needed
                        }

                        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
                    })

                    // Set up the SSL context with the custom TrustManager
                    val sslContext = SSLContext.getInstance("TLS")
                    sslContext.init(null, trustAllCerts, java.security.SecureRandom())

                    // Create an SSLSocketFactory with the custom SSL context
                    val sslSocketFactory = sslContext.socketFactory

                    // Connect to the server
                    val host = "self-signed.badssl.com"
                    val port = 443
                    val socket = sslSocketFactory.createSocket(host, port) as SSLSocket

                    // Start the handshake
                    socket.startHandshake()

                    // Send an HTTP GET request
                    val request = "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
                    val outputStream: OutputStream = socket.outputStream
                    outputStream.write(request.toByteArray())
                    outputStream.flush()

                    // Read the response
                    val inputStream = socket.inputStream
                    val reader = BufferedReader(InputStreamReader(inputStream))
                    val response = reader.readText()

                    // Update the sensitive string with the response
                    sensitiveString = "Connection Successful: ${response.substring(0, minOf(200, response.length))}" // Limit response length
                } catch (e: Exception) {
                    // Log the detailed stack trace for debugging
                    e.printStackTrace()

                    // Update sensitive string with exception details
                    sensitiveString = "Connection Failed: ${e::class.simpleName} - ${e.message}"
                }
            }
        }

        Log.d("MASTG-TEST", sensitiveString)
        return sensitiveString
    }

}
