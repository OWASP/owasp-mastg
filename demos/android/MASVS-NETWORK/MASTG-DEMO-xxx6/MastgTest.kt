package org.owasp.mastestapp

import android.content.Context

import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.InputStream
import java.net.URL
import javax.net.ssl.*

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        var sensitiveString = "Hello from the OWASP MASTG Test app."

        runBlocking {
            withContext(Dispatchers.IO) {
                try {
                    // Load the self-signed certificate
                    val certificateInput: InputStream = context.resources.openRawResource(R.raw.selfsigned)

                    // Create a KeyStore with the certificate
                    val certificateFactory = java.security.cert.CertificateFactory.getInstance("X.509")
                    val certificate = certificateFactory.generateCertificate(certificateInput)
                    val keyStore = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType())
                    keyStore.load(null, null)
                    keyStore.setCertificateEntry("selfsigned", certificate)

                    // Create a TrustManager that trusts the certificate in the KeyStore
                    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                    trustManagerFactory.init(keyStore)
                    val trustManagers = trustManagerFactory.trustManagers

                    // Create an SSLContext with the custom TrustManager
                    val sslContext = SSLContext.getInstance("TLS")
                    sslContext.init(null, trustManagers, null)

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
