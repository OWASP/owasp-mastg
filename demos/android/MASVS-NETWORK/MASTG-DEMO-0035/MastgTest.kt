package com.example.uncrackable_level1_MASTG_NETWORK

import android.R
import android.annotation.SuppressLint
import android.net.http.SslError
import android.os.Bundle
import android.os.StrictMode
import android.os.StrictMode.ThreadPolicy
import android.util.Log
import android.view.Gravity
import android.view.WindowManager
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.LinearLayout
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.uncrackable_level1_MASTG_NETWORK.ui.theme.UnCrackableLevel1Theme
import com.squareup.okhttp.Callback
import com.squareup.okhttp.CipherSuite
import com.squareup.okhttp.ConnectionSpec
import com.squareup.okhttp.OkHttpClient
import com.squareup.okhttp.Request
import com.squareup.okhttp.Response
import com.squareup.okhttp.TlsVersion
import java.io.IOException
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager


class MainActivity : ComponentActivity() {
    @SuppressLint("ServiceCast")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val policy = ThreadPolicy.Builder()
            .permitAll().build()
        StrictMode.setThreadPolicy(policy)
        Log.i(null, "Set content")

        setContent {
            UnCrackableLevel1Theme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    CallInsecureServers()
                }
            }
        }

        val windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        val view = LinearLayout(this)
        view.layoutParams =
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT
            )

        class MyWebViewClient : WebViewClient() {
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                var message = "SSL Certificate error."
                when (error.getPrimaryError()) {
                    SslError.SSL_UNTRUSTED -> message = "The certificate authority is not trusted."
                    SslError.SSL_EXPIRED -> message = "The certificate has expired."
                    SslError.SSL_IDMISMATCH -> message = "The certificate Hostname mismatch."
                    SslError.SSL_NOTYETVALID -> message = "The certificate is not yet valid."
                    SslError.SSL_DATE_INVALID -> message = "The date of the certificate is invalid"
                }
                Log.w(null, "SSL errors onReceivedSslError: ".plus(message))
                Log.w(null, error.toString())

                handler.proceed()
            }
        }

        var webView = WebView(this)
        webView.webViewClient = MyWebViewClient()
        var params = WindowManager.LayoutParams()
        params.gravity = Gravity.TOP or Gravity.LEFT
        params.x = 0
        params.y = 100
        view.addView(webView)
        webView.loadUrl("https://tlsexpired.no")
        //webView.loadUrl("http://tlsrevocation.org")
        //webView.loadUrl("https://tlsrevoked.no")
        //webView.loadUrl("https://tlsbadsubjectaltname.no")
        windowManager.addView(view, params)



    }


}

fun Builder(): OkHttpClient {
    val builder = OkHttpClient()
    try {
        // Create a trust manager that does not validate certificate chains
        val trustAllCerts = arrayOf<TrustManager>(@SuppressLint("CustomX509TrustManager")
        object : X509TrustManager {
            @SuppressLint("TrustAllX509TrustManager")
            @Throws(CertificateException::class)
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                // N / A
                Log.w(null, "Client not trusted")
            }

            @SuppressLint("TrustAllX509TrustManager")
            @Throws(CertificateException::class)
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                // N / A
                Log.w(null, "Server not trusted")
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                Log.w(null, "All issuers accepted")
                return arrayOf()
            }
        })

        // Install the all-trusting trust manager with an insecure protocol
        //val sslContext = SSLContext.getInstance("TLSv1.1")
        val sslContext = SSLContext.getInstance("SSL")

        sslContext.init(null, trustAllCerts, SecureRandom())
        // Create an ssl socket factory with our all-trusting manager
        val sslSocketFactory = sslContext.socketFactory

        builder.setSslSocketFactory(sslSocketFactory)

        val allowallhostnameverifier = HostnameVerifier { hostname, session ->
            Log.w(null, "Do not verify host, allow: ".plus(hostname))
            true
        }
        builder.setHostnameVerifier(allowallhostnameverifier)


    } catch (e: Exception) {
        Log.w(null, e)
    }
    val spec = ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
        .tlsVersions(TlsVersion.TLS_1_2)
        .cipherSuites(
            CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_DES_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_NULL_SHA,
            CipherSuite.TLS_RSA_WITH_NULL_MD5,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
            CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
            CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
            CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        )
        .build()
    builder.setConnectionSpecs(Collections.singletonList(spec))
    return builder
}

fun ClearTextBuilder(): OkHttpClient {
    val builder = OkHttpClient();
    try {
        // Create a trust manager that does not validate certificate chains
        val trustAllCerts = arrayOf<TrustManager>(@SuppressLint("CustomX509TrustManager")
        object : X509TrustManager {
            @SuppressLint("TrustAllX509TrustManager")
            @Throws(CertificateException::class)
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                // N / A
                Log.w(null, "Client not trusted")
            }

            @SuppressLint("TrustAllX509TrustManager")
            @Throws(CertificateException::class)
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                // N / A
                Log.w(null, "Server not trusted")
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                Log.w(null, "All issuers accepted")
                return arrayOf()
            }
        })

        // Install the all-trusting trust manager with an insecure protocol
        val sslContext = SSLContext.getInstance("TLSv1.1")
        sslContext.init(null, trustAllCerts, SecureRandom())
        // Create an ssl socket factory with our all-trusting manager
        val sslSocketFactory = sslContext.socketFactory


        builder.setSslSocketFactory(sslSocketFactory)

        val allowallhostnameverifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;

        builder.setHostnameVerifier(allowallhostnameverifier)


    } catch (e: Exception) {
        Log.w(null, e)
    }
    val spec = ConnectionSpec.Builder(ConnectionSpec.CLEARTEXT)
        .build()
    builder.setConnectionSpecs(Collections.singletonList(spec))
    return builder
}

@Composable
fun CallInsecureServers(modifier: Modifier = Modifier) {
    val content = "Response:"

    val tlsRevocationRequest = Request.Builder()
        .header("User-Agent", "COOL APP 9000")
        //Non encrypted connection
        .url("http://tlsrevocation.org").build()
    val tlsRevocationResponse = ClearTextBuilder().newCall(tlsRevocationRequest).execute()?.body()!!.string()

    val tlsExpiredRequest = Request.Builder()
        .header("User-Agent", "COOL APP 9000")
        //Expired certificate
        .url("https://tlsexpired.no").build()
    val tlsExpiredResponse = Builder().newCall(tlsExpiredRequest).execute()?.body()!!.string()

    val tlsRevokedRequest = Request.Builder()
        .header("User-Agent", "COOL APP 9000")
        //Revoked certificate
        .url("https://tlsrevoked.no").build()
    val tlsRevokedResponse = Builder().newCall(tlsRevokedRequest).execute()?.body()!!.string()

    val tlsBadSubjectAltNamerequest = Request.Builder()
        .header("User-Agent", "COOL APP 9000")
        //Certificate with wrong subject alt name
        .url("https://tlsbadsubjectaltname.no").build()
    val tlsBadSubjectAltNameResponse = Builder().newCall(tlsBadSubjectAltNamerequest).execute()?.body()!!.string()

    Surface(color = Color.Cyan) {
        Text(
            text = content.plus("\n\n")
               .plus(tlsRevocationResponse).plus("\n\n")
                .plus(tlsExpiredResponse).plus("\n\n")
                .plus(tlsRevokedResponse).plus("\n\n")
                .plus(tlsBadSubjectAltNameResponse).plus("\n\n"),
            modifier = modifier.padding(24.dp)
        )
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    Log.i(null, "Set preview")
    UnCrackableLevel1Theme {
        CallInsecureServers()
    }
}