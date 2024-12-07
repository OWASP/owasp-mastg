package org.owasp.mastestapp

import android.util.Log
import android.content.Context
import android.net.http.SslError
import android.webkit.SslErrorHandler

import android.webkit.WebView
import android.webkit.WebViewClient

class MastgTest (private val context: Context){

    fun mastgTest(webView: WebView? = null): String {
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
        return "MastgTest"
    }

}
