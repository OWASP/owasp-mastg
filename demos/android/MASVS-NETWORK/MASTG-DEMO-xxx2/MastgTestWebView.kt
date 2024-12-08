package org.owasp.mastestapp

import android.content.Context
import android.net.http.SslCertificate
import android.net.http.SslError
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class MastgTestWebView(private val context: Context) {

    fun mastgTest(webView: WebView) {
        webView.apply {
            webViewClient = object : WebViewClient() {
                override fun onReceivedSslError(
                    view: WebView?,
                    handler: SslErrorHandler?,
                    error: SslError?
                ) {
                    try {
                        // Load the pinned certificate
                        val pinnedCertInputStream = view?.context?.resources?.openRawResource(R.raw.selfsigned)
                        val certificateFactory = CertificateFactory.getInstance("X.509")
                        val pinnedCert = certificateFactory.generateCertificate(pinnedCertInputStream)

                        // Extract the server's certificate
                        val serverCert = error?.certificate?.let { sslCertificate ->
                            val bundle = SslCertificate.saveState(sslCertificate)
                            val bytes = bundle.getByteArray("x509-certificate")
                            bytes?.let {
                                certificateFactory.generateCertificate(ByteArrayInputStream(it)) as? X509Certificate
                            }
                        }

                        // Compare the certificates
                        if (serverCert != null && serverCert == pinnedCert) {
                            Log.d("MASTG-TEST", "Certificates match, proceeding")
                            handler?.proceed() // Certificates match, proceed
                        } else {
                            Log.d("MASTG-TEST", "Certificates don't match, cancelling")
                            handler?.cancel() // Certificates don't match, cancel
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                        handler?.cancel() // Cancel on error
                    }
                }
            }
            // loadUrl("https://expired.badssl.com/")      // Certificates don't match, cancel
            loadUrl("https://self-signed.badssl.com/")  // Certificates match, proceed
        }
    }
}
