package org.owasp.mastestapp

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class MastgTest(private val context: Context) {

    fun mastgTest(): String {
        var socket: SSLSocket? = null

        return try {
            // Use the default SSLSocketFactory
            val sslSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory

            // Connect to the server using SSLSocket
            val host = "wrong.host.badssl.com"
            val port = 443
            socket = sslSocketFactory.createSocket(host, port) as SSLSocket

            // Start the handshake
            socket.startHandshake()

            val hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
            val session = socket.session
            if (!hostnameVerifier.verify(host, session)) {
                throw SSLException("Hostname verification failed for host: $host")
            }

            // Send an HTTP GET request
            val request = "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n"
            val out = socket.outputStream
            out.write(request.toByteArray())
            out.flush()

            // Read the response (this will read until the server closes)
            val reader = BufferedReader(InputStreamReader(socket.inputStream))
            val response = reader.readText()

            "Connection Successful: ${response.substring(0, minOf(200, response.length))}"
        } catch (e: Exception) {
            e.printStackTrace()
            "Connection Failed: ${e::class.simpleName} - ${e.message}"
        } finally {
            // Clean up: close the socket
            socket?.let {
                try { it.close() } catch (_: Exception) {}
            }
        }
    }
}
