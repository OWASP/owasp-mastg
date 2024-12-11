package org.owasp.mastestapp

import android.content.Context
import android.net.http.SslError
import android.webkit.SslErrorHandler

import android.webkit.WebViewClient

class MastgTestWebView (private val context: Context){

    fun mastgTest(webView: WebView) {
        webView?.apply {
            webViewClient = object : WebViewClient() { }

            loadUrl("http://http.badssl.com/")

        }
    }

}
