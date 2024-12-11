package org.owasp.mastestapp

import android.content.Context
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.*

class MastgTest(private val context: Context) {

    fun mastgTest(): String {
        var result = ""

        runBlocking {
            withContext(Dispatchers.IO) {
                try {
                    // Create a URL connection
                    val url = URL("https://tls-v1-2.badssl.com:1012/")
                    val connection = (url.openConnection() as HttpsURLConnection).apply {
                        sslSocketFactory = Tls12SocketFactory(SSLSocketFactory.getDefault() as SSLSocketFactory)
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

    class Tls12SocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {

        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        override fun createSocket(s: java.net.Socket?, host: String?, port: Int, autoClose: Boolean): java.net.Socket =
            configureSocket(delegate.createSocket(s, host, port, autoClose))

        override fun createSocket(host: String?, port: Int): java.net.Socket =
            configureSocket(delegate.createSocket(host, port))

        override fun createSocket(host: String?, port: Int, localAddress: java.net.InetAddress?, localPort: Int): java.net.Socket =
            configureSocket(delegate.createSocket(host, port, localAddress, localPort))

        override fun createSocket(address: java.net.InetAddress?, port: Int): java.net.Socket =
            configureSocket(delegate.createSocket(address, port))

        override fun createSocket(
            address: java.net.InetAddress?,
            port: Int,
            localAddress: java.net.InetAddress?,
            localPort: Int
        ): java.net.Socket = configureSocket(delegate.createSocket(address, port, localAddress, localPort))

        private fun configureSocket(socket: java.net.Socket): java.net.Socket {
            if (socket is SSLSocket) {
                socket.enabledProtocols = arrayOf("TLSv1.2")
                socket.startHandshake()
                val tlsVersion = socket.session.protocol
                println("TLS Version Used: $tlsVersion")
            }
            return socket
        }
    }
}

