package org.owasp.mastestapp;

import android.content.Context;
import android.util.Log;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import kotlin.Metadata;
import kotlin.io.CloseableKt;
import kotlin.io.TextStreamsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\u0006\u001a\u00020\u0007J\u0010\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u0007H\u0002J\u0010\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\rH\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000e"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "mastgTest", "", "fetchUrl", "urlString", "trustAllCertificates", "", "connection", "Ljavax/net/ssl/HttpsURLConnection;", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() throws InterruptedException {
        final StringBuilder content = new StringBuilder("Response:\n\n");
        Thread thread = new Thread(new Runnable() { // from class: org.owasp.mastestapp.MastgTest$$ExternalSyntheticLambda1
            @Override // java.lang.Runnable
            public final void run() {
                MastgTest.mastgTest$lambda$0(content, this);
            }
        });
        thread.start();
        thread.join();
        String string = content.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void mastgTest$lambda$0(StringBuilder content, MastgTest this$0) {
        Intrinsics.checkNotNullParameter(content, "$content");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        content.append(this$0.fetchUrl("https://tlsbadsubjectaltname.no"));
    }

    private final String fetchUrl(String urlString) throws IOException {
        try {
            URL url = new URL(urlString);
            URLConnection uRLConnectionOpenConnection = url.openConnection();
            Intrinsics.checkNotNull(uRLConnectionOpenConnection, "null cannot be cast to non-null type javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection connection = (HttpsURLConnection) uRLConnectionOpenConnection;
            trustAllCertificates(connection);
            connection.setHostnameVerifier(new HostnameVerifier() { // from class: org.owasp.mastestapp.MastgTest$$ExternalSyntheticLambda0
                @Override // javax.net.ssl.HostnameVerifier
                public final boolean verify(String str, SSLSession sSLSession) {
                    return MastgTest.fetchUrl$lambda$1(str, sSLSession);
                }
            });
            connection.setRequestProperty("User-Agent", "OWASP MAS APP 9000");
            connection.connect();
            InputStream inputStream = connection.getInputStream();
            Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
            Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
            BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
            try {
                BufferedReader it = bufferedReader;
                String response = TextStreamsKt.readText(it);
                CloseableKt.closeFinally(bufferedReader, null);
                return "\n[" + urlString + "] Response OK\n" + response + "\n";
            } finally {
            }
        } catch (Exception e) {
            return "\n[" + urlString + "] Error: " + e.getMessage() + "\n";
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final boolean fetchUrl$lambda$1(String hostname, SSLSession sSLSession) {
        Log.w("HOSTNAME_VERIFIER", "Insecurely allowing host: " + hostname);
        return true;
    }

    private final void trustAllCertificates(HttpsURLConnection connection) throws NoSuchAlgorithmException, KeyManagementException {
        try {
            TrustManager[] trustAllCerts = {new X509TrustManager() { // from class: org.owasp.mastestapp.MastgTest$trustAllCertificates$trustAllCerts$1
                @Override // javax.net.ssl.X509TrustManager
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override // javax.net.ssl.X509TrustManager
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override // javax.net.ssl.X509TrustManager
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }};
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
        } catch (Exception e) {
            Log.e("TRUST_MANAGER", "Failed to setup trust manager: " + e.getMessage());
        }
    }
}
