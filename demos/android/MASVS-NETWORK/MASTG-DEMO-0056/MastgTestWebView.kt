package org.owasp.mastestapp

import android.content.Context
import android.net.http.SslError
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient

class MastgTestWebView(private val context: Context) {

    fun mastgTest(webView: WebView) {
        webView.apply {
            webViewClient = object : WebViewClient() {
                override fun onReceivedSslError(
                    view: WebView,
                    handler: SslErrorHandler,
                    error: SslError
                ) {
                    val message = getSslErrorMessage(error)

                    Log.e("MastgTestWebView", "SSL errors onReceivedSslError: $message")
                    Log.e("MastgTestWebView", error.toString())

                    handler.proceed()
                }
            }
            loadUrl("https://tlsexpired.no")
        }
    }

    private fun getSslErrorMessage(error: SslError): String = when (error.primaryError) {
        SslError.SSL_UNTRUSTED      -> "The certificate authority is not trusted."
        SslError.SSL_EXPIRED        -> "The certificate has expired."
        SslError.SSL_IDMISMATCH     -> "The certificate Hostname mismatch."
        SslError.SSL_NOTYETVALID    -> "The certificate is not yet valid."
        SslError.SSL_DATE_INVALID   -> "The date of the certificate is invalid."
        else                        -> "SSL Certificate error."
    }
}