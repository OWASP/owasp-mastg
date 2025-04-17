package org.owasp.mastestapp

import android.net.http.SslError
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import android.content.Context

class MastgTestWebView (private val context: Context,) {

    fun mastgTest(webView: WebView) {
        webView.apply {
            webViewClient = object : WebViewClient() {
                override fun onReceivedSslError(
                    view: WebView,
                    handler: SslErrorHandler,
                    error: SslError
                ) {
                    var message = "SSL Certificate error."
                    when (error.getPrimaryError()) {
                        SslError.SSL_UNTRUSTED -> message =
                            "The certificate authority is not trusted."

                        SslError.SSL_EXPIRED -> message = "The certificate has expired."
                        SslError.SSL_IDMISMATCH -> message = "The certificate Hostname mismatch."
                        SslError.SSL_NOTYETVALID -> message = "The certificate is not yet valid."
                        SslError.SSL_DATE_INVALID -> message =
                            "The date of the certificate is invalid"
                    }
                    Log.w(null, "SSL errors onReceivedSslError: ".plus(message))
                    Log.w(null, error.toString())

                    handler.proceed()
                }

            }
            loadUrl("https://tlsexpired.no")
        }
    }
}