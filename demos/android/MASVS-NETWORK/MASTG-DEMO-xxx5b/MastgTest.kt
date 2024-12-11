package org.owasp.mastestapp

import android.content.Context
import android.webkit.*
import java.io.BufferedInputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.*

class MastgTestWebView(private val context: Context) {

    fun mastgTest(webView: WebView) {
        webView.apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true

            webViewClient = object : WebViewClient() {
                override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
                    val interceptedUrl = request?.url.toString()
                    println("Intercepting URL: $interceptedUrl")
                    return if (interceptedUrl.startsWith("https://")) {
                        handleHttpRequest(interceptedUrl)
                    } else {
                        super.shouldInterceptRequest(view, request)
                    }
                }
            }

            loadData(
                """
                <html>
                    <body>
                        <h1>Intercept XMLHttpRequest</h1>
                        <p>Waiting for response...</p>
                        <script>
                            // Enhanced fetch with error details
                            var xhr = new XMLHttpRequest();
                            xhr.open('GET', 'https://self-signed.badssl.com', true);
                            xhr.onreadystatechange = function () {
                                if (xhr.readyState === 4) {
                                    if (xhr.status === 200) {
                                        document.body.innerHTML += '<h1>Response:</h1><pre>' + xhr.responseText + '</pre>';
                                    } else {
                                        document.body.innerHTML += '<h1>Error:</h1><pre>' + xhr.status + ' - ' + xhr.statusText + '</pre>';
                                    }
                                }
                            };
                            xhr.onerror = function () {
                                document.body.innerHTML += '<h1>Error:</h1><pre>Network error occurred</pre>';
                            };
                            xhr.send();
                        </script>
                    </body>
                </html>
                """.trimIndent(),
                "text/html",
                "UTF-8"
            )
        }
    }

    private fun handleHttpRequest(url: String): WebResourceResponse? {
        println("Attempting to fetch URL: $url")
        return try {
            val connection = (URL(url).openConnection() as HttpURLConnection).apply {
                if (this is HttpsURLConnection) {
                    sslSocketFactory = TrustAllSslSocketFactory.sslSocketFactory
                    hostnameVerifier = HostnameVerifier { _, _ -> true }
                }
                requestMethod = "GET"
                connect()
            }

            val contentType = connection.contentType ?: "text/html"
            val encoding = connection.contentEncoding ?: "UTF-8"
            val inputStream: InputStream = BufferedInputStream(connection.inputStream)

            // Log headers
            connection.headerFields.forEach { (key, value) ->
                println("Header: $key -> $value")
            }

            // Add essential CORS headers for fetch
            val headers = mapOf(
                "Access-Control-Allow-Origin" to "*",
                "Access-Control-Allow-Methods" to "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers" to "Content-Type, Authorization"
            )

            WebResourceResponse(contentType, encoding, inputStream).apply {
                responseHeaders = headers
            }
        } catch (e: Exception) {
            println("Error fetching URL: $e")
            null
        }
    }

    object TrustAllSslSocketFactory {
        val sslSocketFactory: SSLSocketFactory by lazy {
            val trustAllCerts = arrayOf<TrustManager>(
                object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
                }
            )
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, trustAllCerts, java.security.SecureRandom())
            sslContext.socketFactory
        }
    }
}
