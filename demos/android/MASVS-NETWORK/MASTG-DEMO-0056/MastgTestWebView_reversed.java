package org.owasp.mastestapp;

import android.content.Context;
import android.net.http.SslError;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTestWebView.kt */
@Metadata(d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u000e\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tJ\u0010\u0010\n\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\rH\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000e"}, d2 = {"Lorg/owasp/mastestapp/MastgTestWebView;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "mastgTest", "", "webView", "Landroid/webkit/WebView;", "getSslErrorMessage", "", "error", "Landroid/net/http/SslError;", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTestWebView {
    public static final int $stable = 8;
    private final Context context;

    public MastgTestWebView(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final void mastgTest(WebView webView) {
        Intrinsics.checkNotNullParameter(webView, "webView");
        webView.setWebViewClient(new WebViewClient() { // from class: org.owasp.mastestapp.MastgTestWebView$mastgTest$1$1
            @Override // android.webkit.WebViewClient
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(handler, "handler");
                Intrinsics.checkNotNullParameter(error, "error");
                String message = this.this$0.getSslErrorMessage(error);
                Log.e("MastgTestWebView", "SSL errors onReceivedSslError: " + message);
                Log.e("MastgTestWebView", error.toString());
                handler.proceed();
            }
        });
        webView.loadUrl("https://tlsexpired.no");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getSslErrorMessage(SslError error) {
        switch (error.getPrimaryError()) {
            case 0:
                return "The certificate is not yet valid.";
            case 1:
                return "The certificate has expired.";
            case 2:
                return "The certificate Hostname mismatch.";
            case 3:
                return "The certificate authority is not trusted.";
            case 4:
                return "The date of the certificate is invalid.";
            default:
                return "SSL Certificate error.";
        }
    }
}
