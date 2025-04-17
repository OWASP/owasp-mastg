package org.owasp.mastestapp

import android.annotation.SuppressLint
import android.util.Log
import com.squareup.okhttp.CipherSuite
import com.squareup.okhttp.ConnectionSpec
import com.squareup.okhttp.OkHttpClient
import com.squareup.okhttp.Request
import com.squareup.okhttp.TlsVersion
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Collections
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import android.content.Context

import org.apache.http.conn.ssl.SSLSocketFactory

class MastgTest (private val context: Context,) {

    fun mastgTest(): String {
        val content = "Response:"
        val tlsRevocationResponse = ""
        val tlsExpiredResponse = ""
        val tlsRevokedResponse = ""
        val tlsBadSubjectAltNameResponse = ""
        Thread({
            val tlsRevocationRequest = Request.Builder()
                .header("User-Agent", "COOL APP 9000")
                //Non encrypted connection
                .url("http://tlsrevocation.org").build()
            tlsRevocationResponse.plus(
                ClearTextBuilder().newCall(tlsRevocationRequest).execute()?.body()!!.string())

            val tlsExpiredRequest = Request.Builder()
                .header("User-Agent", "COOL APP 9000")
                //Expired certificate
                .url("https://tlsexpired.no").build()
            tlsExpiredResponse.plus(Builder().newCall(tlsExpiredRequest).execute()?.body()!!.string())

            val tlsRevokedRequest = Request.Builder()
                .header("User-Agent", "COOL APP 9000")
                //Revoked certificate
                .url("https://tlsrevoked.no").build()
            tlsRevokedResponse.plus(Builder().newCall(tlsRevokedRequest).execute()?.body()!!.string())

            val tlsBadSubjectAltNamerequest = Request.Builder()
                .header("User-Agent", "COOL APP 9000")
                //Certificate with wrong subject alt name
                .url("https://tlsbadsubjectaltname.no").build()
            tlsBadSubjectAltNameResponse.plus(Builder().newCall(tlsBadSubjectAltNamerequest).execute()?.body()!!.string())


        }).start()
        return content.plus("\n\n")
            .plus(tlsRevocationResponse).plus("\n\n")
            .plus(tlsExpiredResponse).plus("\n\n")
            .plus(tlsRevokedResponse).plus("\n\n")
            .plus(tlsBadSubjectAltNameResponse).plus("\n\n")
    }

    fun Builder(): OkHttpClient {
        val builder = OkHttpClient()
        try {
            // Create a trust manager that does not validate certificate chains
            val trustAllCerts = arrayOf<TrustManager>(
                @SuppressLint("CustomX509TrustManager")
                object : X509TrustManager {
                    @SuppressLint("TrustAllX509TrustManager")
                    @Throws(CertificateException::class)
                    override fun checkClientTrusted(
                        chain: Array<X509Certificate>,
                        authType: String
                    ) {
                        // N / A
                        Log.w(null, "Client not trusted")
                    }

                    @SuppressLint("TrustAllX509TrustManager")
                    @Throws(CertificateException::class)
                    override fun checkServerTrusted(
                        chain: Array<X509Certificate>,
                        authType: String
                    ) {
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
            val trustAllCerts = arrayOf<TrustManager>(
                @SuppressLint("CustomX509TrustManager")
                object : X509TrustManager {
                    @SuppressLint("TrustAllX509TrustManager")
                    @Throws(CertificateException::class)
                    override fun checkClientTrusted(
                        chain: Array<X509Certificate>,
                        authType: String
                    ) {
                        // N / A
                        Log.w(null, "Client not trusted")
                    }

                    @SuppressLint("TrustAllX509TrustManager")
                    @Throws(CertificateException::class)
                    override fun checkServerTrusted(
                        chain: Array<X509Certificate>,
                        authType: String
                    ) {
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

            val allowallhostnameverifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;

            builder.setHostnameVerifier(allowallhostnameverifier)


        } catch (e: Exception) {
            Log.w(null, e)
        }
        val spec = ConnectionSpec.Builder(ConnectionSpec.CLEARTEXT)
            .build()
        builder.setConnectionSpecs(Collections.singletonList(spec))
        return builder
    }
}