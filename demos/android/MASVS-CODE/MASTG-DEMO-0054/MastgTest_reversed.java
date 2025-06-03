package org.owasp.mastestapp;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import java.util.HashSet;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.collections.SetsKt;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\b\u001a\u00020\tJ\b\u0010\n\u001a\u00020\u000bH\u0002J\b\u0010\f\u001a\u00020\u000bH\u0002J\b\u0010\r\u001a\u00020\u000bH\u0002J\b\u0010\u000e\u001a\u00020\u000bH\u0002J\b\u0010\u000f\u001a\u00020\tH\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0010"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "sharedPref", "Landroid/content/SharedPreferences;", "mastgTest", "", "storePrimitiveTypes", "", "storeStrings", "storeStringSet", "simulateTampering", "retrieveAndVerifyData", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;
    private final SharedPreferences sharedPref;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        SharedPreferences sharedPreferences = this.context.getSharedPreferences("DemoPrefs", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.sharedPref = sharedPreferences;
    }

    public final String mastgTest() {
        storePrimitiveTypes();
        storeStrings();
        storeStringSet();
        simulateTampering();
        return retrieveAndVerifyData();
    }

    private final void storePrimitiveTypes() {
        SharedPreferences.Editor $this$storePrimitiveTypes_u24lambda_u240 = this.sharedPref.edit();
        $this$storePrimitiveTypes_u24lambda_u240.putInt("appLaunchCount", 5);
        $this$storePrimitiveTypes_u24lambda_u240.putBoolean("isPremiumUser", false);
        $this$storePrimitiveTypes_u24lambda_u240.putLong("lastLoginTime", System.currentTimeMillis());
        $this$storePrimitiveTypes_u24lambda_u240.apply();
        Log.d("MASTG-TEST", "Stored primitive types");
    }

    private final void storeStrings() {
        SharedPreferences.Editor $this$storeStrings_u24lambda_u241 = this.sharedPref.edit();
        $this$storeStrings_u24lambda_u241.putString("userJson", "{\"name\":\"John\",\"admin\":false}");
        $this$storeStrings_u24lambda_u241.putString("htmlContent", "<div>Safe content</div>");
        $this$storeStrings_u24lambda_u241.apply();
        Log.d("MASTG-TEST", "Stored strings");
    }

    private final void storeStringSet() {
        HashSet stringSet = new HashSet();
        stringSet.add("normal_item");
        stringSet.add("another_item");
        this.sharedPref.edit().putStringSet("itemSet", stringSet).apply();
        Log.d("MASTG-TEST", "Stored string set");
    }

    private final void simulateTampering() {
        SharedPreferences prefsFile = this.context.getSharedPreferences("DemoPrefs", 0);
        SharedPreferences.Editor $this$simulateTampering_u24lambda_u242 = prefsFile.edit();
        $this$simulateTampering_u24lambda_u242.putInt("appLaunchCount", 9999);
        $this$simulateTampering_u24lambda_u242.putBoolean("isPremiumUser", true);
        $this$simulateTampering_u24lambda_u242.putString("userJson", "{\"name\":\"John\",\"admin\":true}");
        $this$simulateTampering_u24lambda_u242.putString("htmlContent", "<script>alert('XSS')</script>");
        HashSet maliciousSet = new HashSet();
        maliciousSet.add("normal_item");
        maliciousSet.add("malicious_payload");
        $this$simulateTampering_u24lambda_u242.putStringSet("itemSet", maliciousSet);
        $this$simulateTampering_u24lambda_u242.apply();
        Log.d("MASTG-TEST", "Simulated tampering with all data types");
    }

    private final String retrieveAndVerifyData() {
        StringBuilder result = new StringBuilder();
        result.append("Primitive Types:\n").append("Launch Count: " + this.sharedPref.getInt("appLaunchCount", 0) + "\n").append("Is Premium: " + this.sharedPref.getBoolean("isPremiumUser", false) + "\n\n");
        result.append("Strings:\n");
        String userJson = this.sharedPref.getString("userJson", "");
        result.append("User JSON: " + userJson + "\n");
        String htmlContent = this.sharedPref.getString("htmlContent", "");
        result.append("HTML Content: " + htmlContent + "\n\n");
        result.append("String Set:\n");
        Set itemSet = this.sharedPref.getStringSet("itemSet", SetsKt.emptySet());
        result.append("Items: " + (itemSet != null ? CollectionsKt.joinToString$default(itemSet, null, null, null, 0, null, null, 63, null) : null));
        String sb = result.toString();
        Intrinsics.checkNotNullExpressionValue(sb, "toString(...)");
        return sb;
    }
}