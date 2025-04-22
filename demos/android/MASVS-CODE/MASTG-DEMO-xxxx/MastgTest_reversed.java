package org.owasp.mastestapp;

import android.content.Context;
import android.util.Log;
import androidx.autofill.HintConstants;
import java.io.File;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.TuplesKt;
import kotlin.collections.MapsKt;
import kotlin.io.FilesKt;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0004\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\t\u001a\u00020\nJ\u0012\u0010\u000b\u001a\u000e\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\b0\u0007J\u0006\u0010\f\u001a\u00020\nJ\u0006\u0010\r\u001a\u00020\bR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\u0006\u001a\u000e\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\b0\u0007X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000e"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "sensitiveData", "", "", "storeSensitiveDataInsecurely", "", "loadSensitiveDataInsecurely", "storeSensitiveArrayInsecurely", "mastgTest", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;
    private final Map<String, String> sensitiveData;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        this.sensitiveData = MapsKt.mapOf(TuplesKt.to(HintConstants.AUTOFILL_HINT_USERNAME, "admin"), TuplesKt.to(HintConstants.AUTOFILL_HINT_PASSWORD, "SuperSecret123!"), TuplesKt.to("api_key", "AKIAIOSFODNN7EXAMPLE"), TuplesKt.to("auth_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."));
    }

    public final boolean storeSensitiveDataInsecurely() {
        try {
            Map<String, String> map = this.sensitiveData;
            Intrinsics.checkNotNull(map, "null cannot be cast to non-null type kotlin.collections.Map<*, *>");
            JSONObject jsonData = new JSONObject(map);
            File file = new File(this.context.getFilesDir(), "config.json");
            String jSONObject = jsonData.toString();
            Intrinsics.checkNotNullExpressionValue(jSONObject, "toString(...)");
            FilesKt.writeText$default(file, jSONObject, null, 2, null);
            Log.d("MASTG-TEST", "Sensitive data stored insecurely at: " + file.getAbsolutePath());
            return true;
        } catch (Exception e) {
            Log.e("MASTG-TEST", "Error storing data", e);
            return false;
        }
    }

    public final Map<String, String> loadSensitiveDataInsecurely() {
        try {
            File file = new File(this.context.getFilesDir(), "config.json");
            String jsonString = FilesKt.readText$default(file, null, 1, null);
            JSONObject jsonData = new JSONObject(jsonString);
            Map result = new LinkedHashMap();
            Iterator keys = jsonData.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                result.put(key, jsonData.getString(key));
            }
            Log.d("MASTG-TEST", "Loaded sensitive data: " + result);
            return result;
        } catch (Exception e) {
            Log.e("MASTG-TEST", "Error loading data", e);
            return MapsKt.emptyMap();
        }
    }

    public final boolean storeSensitiveArrayInsecurely() {
        try {
            JSONArray jsonArray = new JSONArray();
            jsonArray.put(new JSONObject(MapsKt.mapOf(TuplesKt.to("credit_card", "4111111111111111"), TuplesKt.to("cvv", "123"))));
            jsonArray.put(new JSONObject(MapsKt.mapOf(TuplesKt.to("credit_card", "5555555555554444"), TuplesKt.to("cvv", "456"))));
            File file = new File(this.context.getFilesDir(), "transactions.json");
            String jSONArray = jsonArray.toString();
            Intrinsics.checkNotNullExpressionValue(jSONArray, "toString(...)");
            FilesKt.writeText$default(file, jSONArray, null, 2, null);
            Log.d("MASTG-TEST", "Sensitive array stored insecurely at: " + file.getAbsolutePath());
            return true;
        } catch (Exception e) {
            Log.e("MASTG-TEST", "Error storing array", e);
            return false;
        }
    }

    public final String mastgTest() {
        storeSensitiveDataInsecurely();
        loadSensitiveDataInsecurely();
        storeSensitiveArrayInsecurely();
        return "MASTG Test completed successfully. Check logs for details.";
    }
}
