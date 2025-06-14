package org.owasp.mastestapp;

import android.content.Context;
import android.util.Log;
import com.squareup.okhttp.CipherSuite;
import com.squareup.okhttp.ConnectionSpec;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.ResponseBody;
import com.squareup.okhttp.TlsVersion;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.apache.http.conn.ssl.X509HostnameVerifier;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\u0006\u001a\u00020\u0007J\u0006\u0010\b\u001a\u00020\tJ\u0006\u0010\n\u001a\u00020\tR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "mastgTest", "", "Builder", "Lcom/squareup/okhttp/OkHttpClient;", "ClearTextBuilder", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() {
        final String tlsRevocationResponse = "";
        final String tlsExpiredResponse = "";
        final String tlsRevokedResponse = "";
        final String tlsBadSubjectAltNameResponse = "";
        new Thread(new Runnable() { // from class: org.owasp.mastestapp.MastgTest$$ExternalSyntheticLambda1
            @Override // java.lang.Runnable
            public final void run() throws IOException {
                MastgTest.mastgTest$lambda$0(tlsRevocationResponse, this, tlsExpiredResponse, tlsRevokedResponse, tlsBadSubjectAltNameResponse);
            }
        }).start();
        return "Response:\n\n\n\n\n\n\n\n\n\n";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void mastgTest$lambda$0(String tlsRevocationResponse, MastgTest this$0, String tlsExpiredResponse, String tlsRevokedResponse, String tlsBadSubjectAltNameResponse) throws IOException {
        Intrinsics.checkNotNullParameter(tlsRevocationResponse, "$tlsRevocationResponse");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(tlsExpiredResponse, "$tlsExpiredResponse");
        Intrinsics.checkNotNullParameter(tlsRevokedResponse, "$tlsRevokedResponse");
        Intrinsics.checkNotNullParameter(tlsBadSubjectAltNameResponse, "$tlsBadSubjectAltNameResponse");
        Request tlsRevocationRequest = new Request.Builder().header("User-Agent", "COOL APP 9000").url("http://tlsrevocation.org").build();
        Response responseExecute = this$0.ClearTextBuilder().newCall(tlsRevocationRequest).execute();
        ResponseBody responseBodyBody = responseExecute != null ? responseExecute.body() : null;
        Intrinsics.checkNotNull(responseBodyBody);
        String str = tlsRevocationResponse + responseBodyBody.string();
        Request tlsExpiredRequest = new Request.Builder().header("User-Agent", "COOL APP 9000").url("https://tlsexpired.no").build();
        Response responseExecute2 = this$0.Builder().newCall(tlsExpiredRequest).execute();
        ResponseBody responseBodyBody2 = responseExecute2 != null ? responseExecute2.body() : null;
        Intrinsics.checkNotNull(responseBodyBody2);
        String str2 = tlsExpiredResponse + responseBodyBody2.string();
        Request tlsRevokedRequest = new Request.Builder().header("User-Agent", "COOL APP 9000").url("https://tlsrevoked.no").build();
        Response responseExecute3 = this$0.Builder().newCall(tlsRevokedRequest).execute();
        ResponseBody responseBodyBody3 = responseExecute3 != null ? responseExecute3.body() : null;
        Intrinsics.checkNotNull(responseBodyBody3);
        String str3 = tlsRevokedResponse + responseBodyBody3.string();
        Request tlsBadSubjectAltNamerequest = new Request.Builder().header("User-Agent", "COOL APP 9000").url("https://tlsbadsubjectaltname.no").build();
        Response responseExecute4 = this$0.Builder().newCall(tlsBadSubjectAltNamerequest).execute();
        ResponseBody responseBodyBody4 = responseExecute4 != null ? responseExecute4.body() : null;
        Intrinsics.checkNotNull(responseBodyBody4);
        String str4 = tlsBadSubjectAltNameResponse + responseBodyBody4.string();
    }

    public final OkHttpClient Builder() throws NoSuchAlgorithmException, KeyManagementException {
        OkHttpClient builder = new OkHttpClient();
        try {
            TrustManager[] trustAllCerts = {new X509TrustManager() { // from class: org.owasp.mastestapp.MastgTest$Builder$trustAllCerts$1
                @Override // javax.net.ssl.X509TrustManager
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    Intrinsics.checkNotNullParameter(chain, "chain");
                    Intrinsics.checkNotNullParameter(authType, "authType");
                    Log.w((String) null, "Client not trusted");
                }

                @Override // javax.net.ssl.X509TrustManager
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    Intrinsics.checkNotNullParameter(chain, "chain");
                    Intrinsics.checkNotNullParameter(authType, "authType");
                    Log.w((String) null, "Server not trusted");
                }

                @Override // javax.net.ssl.X509TrustManager
                public X509Certificate[] getAcceptedIssuers() {
                    Log.w((String) null, "All issuers accepted");
                    return new X509Certificate[0];
                }
            }};
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            builder.setSslSocketFactory(sslSocketFactory);
            HostnameVerifier allowallhostnameverifier = new HostnameVerifier() { // from class: org.owasp.mastestapp.MastgTest$$ExternalSyntheticLambda0
                @Override // javax.net.ssl.HostnameVerifier
                public final boolean verify(String str, SSLSession sSLSession) {
                    return MastgTest.Builder$lambda$1(str, sSLSession);
                }
            };
            builder.setHostnameVerifier(allowallhostnameverifier);
        } catch (Exception e) {
            Log.w((String) null, e);
        }
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS).tlsVersions(TlsVersion.TLS_1_2).cipherSuites(CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA, CipherSuite.TLS_RSA_WITH_DES_CBC_SHA, CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, CipherSuite.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, CipherSuite.TLS_RSA_WITH_NULL_SHA, CipherSuite.TLS_RSA_WITH_NULL_MD5, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5, CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA, CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256, CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384).build();
        builder.setConnectionSpecs(Collections.singletonList(spec));
        return builder;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean Builder$lambda$1(String hostname, SSLSession session) {
        Log.w((String) null, "Do not verify host, allow: " + hostname);
        return true;
    }

    public final OkHttpClient ClearTextBuilder() throws NoSuchAlgorithmException, KeyManagementException {
        OkHttpClient builder = new OkHttpClient();
        try {
            TrustManager[] trustAllCerts = {new X509TrustManager() { // from class: org.owasp.mastestapp.MastgTest$ClearTextBuilder$trustAllCerts$1
                @Override // javax.net.ssl.X509TrustManager
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    Intrinsics.checkNotNullParameter(chain, "chain");
                    Intrinsics.checkNotNullParameter(authType, "authType");
                    Log.w((String) null, "Client not trusted");
                }

                @Override // javax.net.ssl.X509TrustManager
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    Intrinsics.checkNotNullParameter(chain, "chain");
                    Intrinsics.checkNotNullParameter(authType, "authType");
                    Log.w((String) null, "Server not trusted");
                }

                @Override // javax.net.ssl.X509TrustManager
                public X509Certificate[] getAcceptedIssuers() {
                    Log.w((String) null, "All issuers accepted");
                    return new X509Certificate[0];
                }
            }};
            SSLContext sslContext = SSLContext.getInstance("TLSv1.1");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            builder.setSslSocketFactory(sslSocketFactory);
            X509HostnameVerifier allowallhostnameverifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
            builder.setHostnameVerifier(allowallhostnameverifier);
        } catch (Exception e) {
            Log.w((String) null, e);
        }
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.CLEARTEXT).build();
        builder.setConnectionSpecs(Collections.singletonList(spec));
        return builder;
    }
}
