package org.owasp.mastestapp

import android.content.Context
import java.net.URL
import javax.net.ssl.HttpsURLConnection

class MastgTest(private val context: Context) {

    fun mastgTest(): String {
        val content = StringBuilder("Response:\n\n")
        val thread = Thread {
            content.append(fetchUrl("https://mitm-software.badssl.com/"))
        }
        thread.start()
        thread.join()
        return content.toString()
    }

    private fun fetchUrl(urlString: String): String {
        return try {
            val url = URL(urlString)
            val connection = url.openConnection() as HttpsURLConnection

            connection.setRequestProperty("User-Agent", "OWASP MAS APP 9000")
            connection.connect()

            val response = connection.inputStream.bufferedReader().use { it.readText() }
            "\n[$urlString] Response OK\n$response\n"
        } catch (e: Exception) {
            "\n[$urlString] Error: ${e.message}\n"
        }
    }

}