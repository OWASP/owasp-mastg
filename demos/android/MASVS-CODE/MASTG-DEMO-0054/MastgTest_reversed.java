package org.owasp.mastestapp;

import android.content.Context;
import android.content.SharedPreferences;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\u0006\u001a\u00020\u0007R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\b"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "mastgTest", "", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest_reversed {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest_reversed(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() {
        SharedPreferences prefs = this.context.getSharedPreferences("app_settings", 0);
        if (!prefs.contains("setup_complete")) {
            SecureSharedPreferences insecurePrefs = new SecureSharedPreferences(this.context, false);
            insecurePrefs.saveData("user_role_insecure", "user");
            SecureSharedPreferences securePrefs = new SecureSharedPreferences(this.context, true);
            securePrefs.saveData("user_role_secure", "user");
            Intrinsics.checkNotNull(prefs);
            SharedPreferences.Editor editor$iv = prefs.edit();
            editor$iv.putBoolean("setup_complete", true);
            editor$iv.commit();
            return "INITIAL SETUP COMPLETE.\n\nThe role for both secure and insecure tests has been set to 'user'.\n\nACTION REQUIRED:\n1. Use a file explorer or ADB shell on a rooted device.\n2. Go to: /data/data/org.owasp.mastestapp/shared_prefs/\n3. Open the file: app_settings.xml\n4. Change BOTH <string>user</string> values to <string>admin</string>.\n5. Save the file and run this test again to see the results.";
        }
        StringBuilder results = new StringBuilder();
        results.append("--- VERIFYING SCENARIO 1: 'kind: fail' (No HMAC Protection) ---\n");
        SecureSharedPreferences insecurePrefs2 = new SecureSharedPreferences(this.context, false);
        String insecureRole = insecurePrefs2.loadData("user_role_insecure", "error");
        results.append("Loaded role from 'user_role_insecure': '" + insecureRole + "'\n");
        if (Intrinsics.areEqual(insecureRole, "admin")) {
            results.append(">> OUTCOME: VULNERABLE. The application accepted the tampered 'admin' role because there was no integrity check.\n");
        } else {
            results.append(">> OUTCOME: NOT EXPLOITED. The role is still '" + insecureRole + "'. Please ensure you changed it to 'admin' in the XML file.\n");
        }
        results.append("\n--- VERIFYING SCENARIO 2: 'kind: pass' (HMAC Protection Enabled) ---\n");
        SecureSharedPreferences securePrefs2 = new SecureSharedPreferences(this.context, true);
        String secureRole = securePrefs2.loadData("user_role_secure", "tampering_detected");
        results.append("Loaded role from 'user_role_secure': '" + secureRole + "'\n");
        if (Intrinsics.areEqual(secureRole, "tampering_detected")) {
            results.append(">> OUTCOME: SECURE. The application detected that the data was tampered with and correctly rejected the invalid 'admin' role.\n");
        } else if (Intrinsics.areEqual(secureRole, "admin")) {
            results.append(">> OUTCOME: UNEXPECTED. The role is 'admin', which means the HMAC check failed. This should not happen.\n");
        } else {
            results.append(">> OUTCOME: NOT TAMPERED. The role is still '" + secureRole + "', and its HMAC signature is valid.\n");
        }
        results.append("\n\nTest complete. To run the setup again, please clear the application's data in Android Settings and restart the test.");
        String sb = results.toString();
        Intrinsics.checkNotNullExpressionValue(sb, "toString(...)");
        return sb;
    }
}
