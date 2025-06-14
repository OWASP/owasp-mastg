package org.owasp.mastestapp

import android.content.Context
import android.util.Log
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class MastgTest(private val context: Context) {

    fun mastgTest(): String {
        val content = StringBuilder("Response:\n\n")
        val thread = Thread {
            content.append(fetchUrl("https://tlsbadsubjectaltname.no"))
        }
        thread.start()
        thread.join()
        return content.toString()
    }

    private fun fetchUrl(urlString: String): String {
        return try {
            val url = URL(urlString)
            val connection = url.openConnection() as HttpsURLConnection

            // Accept any certificate to bypass CA verification (not the weakness we're showing here)
            trustAllCertificates(connection)

            // ❌ Hostname verification disabled
            connection.hostnameVerifier = HostnameVerifier { hostname, _ ->
                Log.w("HOSTNAME_VERIFIER", "Insecurely allowing host: $hostname")
                true
            }

            connection.setRequestProperty("User-Agent", "OWASP MAS APP 9000")
            connection.connect()

            val response = connection.inputStream.bufferedReader().use { it.readText() }
            "\n[$urlString] Response OK\n$response\n"
        } catch (e: Exception) {
            "\n[$urlString] Error: ${e.message}\n"
        }
    }
    private fun trustAllCertificates(connection: HttpsURLConnection) {
        try {
            val trustAllCerts = arrayOf<TrustManager>(
                object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                }
            )

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, trustAllCerts, SecureRandom())
            connection.sslSocketFactory = sslContext.socketFactory

        } catch (e: Exception) {
            Log.e("TRUST_MANAGER", "Failed to setup trust manager: ${e.message}")
        }
    }
}