package org.owasp.mastestapp;

import android.content.Context;
import android.content.Intent;
import android.util.Log;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\u0006\u001a\u00020\u0007R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\b"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "mastgTest", "", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() {
        Intent vulnerableIntent = new Intent();
        vulnerableIntent.setAction("org.owasp.mastestapp.PROCESS_SENSITIVE_DATA");
        vulnerableIntent.putExtra("sensitive_token", "auth_token_12345");
        vulnerableIntent.putExtra("user_credentials", "admin:password123");
        vulnerableIntent.putExtra("api_key", "sk-1234567890abcdef");
        vulnerableIntent.putExtra("message", "Hello from the OWASP MASTG Test app.");
        try {
            this.context.startActivity(vulnerableIntent);
            Log.d("MASTG-TEST", "Launched vulnerable implicit intent with sensitive data");
        } catch (Exception e) {
            Log.e("MASTG-TEST", "Failed to launch intent: " + e.getMessage());
        }
        Log.d("MASTG-TEST", "Hello from the OWASP MASTG Test app.");
        return "Hello from the OWASP MASTG Test app.";
    }
}
