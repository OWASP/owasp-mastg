package org.owasp.mastestapp

import android.util.Log
import android.content.Context
import android.net.http.SslError
import android.webkit.SslErrorHandler

import android.webkit.WebView
import android.webkit.WebViewClient

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val sensitiveString = "Hello from the OWASP MASTG Test app."

        Log.d("MASTG-TEST", sensitiveString)
        return sensitiveString
    }

    fun setupWebView(webView: WebView) {
        webView.apply {
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
