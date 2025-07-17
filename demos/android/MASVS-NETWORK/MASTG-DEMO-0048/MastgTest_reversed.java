package org.owasp.mastestapp;

import android.content.Context;
import androidx.compose.runtime.ComposerKt;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import kotlin.Metadata;
import kotlin.io.TextStreamsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.Charsets;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0006\u0010\u0005\u001a\u00020\u0006R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0007"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "mastgTest", "", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
/* loaded from: classes4.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() {
        String str;
        SSLSocket socket = null;
        try {
            try {
                SocketFactory socketFactory = SSLSocketFactory.getDefault();
                Intrinsics.checkNotNull(socketFactory, "null cannot be cast to non-null type javax.net.ssl.SSLSocketFactory");
                SSLSocketFactory sslSocketFactory = (SSLSocketFactory) socketFactory;
                Socket createSocket = sslSocketFactory.createSocket("wrong.host.badssl.com", 443);
                Intrinsics.checkNotNull(createSocket, "null cannot be cast to non-null type javax.net.ssl.SSLSocket");
                socket = (SSLSocket) createSocket;
                socket.startHandshake();
                String request = "GET / HTTP/1.1\r\nHost: wrong.host.badssl.com\r\nConnection: close\r\n\r\n";
                OutputStream out = socket.getOutputStream();
                byte[] bytes = request.getBytes(Charsets.UTF_8);
                Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
                out.write(bytes);
                out.flush();
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String response = TextStreamsKt.readText(reader);
                StringBuilder append = new StringBuilder().append("Connection Successful: ");
                String substring = response.substring(0, Math.min(ComposerKt.invocationKey, response.length()));
                Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
                str = append.append(substring).toString();
                try {
                    socket.close();
                } catch (Exception e) {
                }
            } catch (Exception e2) {
                e2.printStackTrace();
                str = "Connection Failed: " + Reflection.getOrCreateKotlinClass(e2.getClass()).getSimpleName() + " - " + e2.getMessage();
                if (socket != null) {
                    SSLSocket it = socket;
                    try {
                        it.close();
                    } catch (Exception e3) {
                    }
                }
            }
            return str;
        } catch (Throwable th) {
            if (socket != null) {
                SSLSocket it2 = socket;
                try {
                    it2.close();
                } catch (Exception e4) {
                }
            }
            throw th;
        }
    }
}
