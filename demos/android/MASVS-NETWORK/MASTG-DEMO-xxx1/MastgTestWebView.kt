package org.owasp.mastestapp

import android.content.Context
import android.net.http.SslError
import android.webkit.SslErrorHandler

import android.webkit.WebViewClient

class MastgTestWebView (private val context: Context){

    fun mastgTest(webView: WebView) {
        webView?.apply {
            webViewClient = object : WebViewClient() {
                override fun onReceivedSslError(
                    view: WebView?,
                    handler: SslErrorHandler?,
                    error: SslError?
                ) {
                    // Proceed with the SSL error (ignore validation)
                    handler?.proceed()
                }
            }

            // loadUrl("https://expired.badssl.com/")
            loadUrl("https://self-signed.badssl.com/")

        }
    }

}
