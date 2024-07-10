package org.owasp.mastestapp;

import android.content.Context;
import android.util.Log;
import androidx.autofill.HintConstants;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.TuplesKt;
import kotlin.collections.CollectionsKt;
import kotlin.collections.MapsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;

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

    /* JADX WARN: Multi-variable type inference failed */
    public final String mastgTest() {
        final Map SENSITIVE_DATA = MapsKt.mapOf(TuplesKt.to("precise_location_latitude", "37.7749"), TuplesKt.to("precise_location_longitude", "-122.4194"), TuplesKt.to(HintConstants.AUTOFILL_HINT_NAME, "John Doe"), TuplesKt.to("email_address", "john.doe@example.com"), TuplesKt.to("phone_number", "+11234567890"), TuplesKt.to("credit_card_number", "1234 5678 9012 3456"));
        final Ref.ObjectRef result = new Ref.ObjectRef();
        result.element = "";
        Thread thread = new Thread(new Runnable() { // from class: org.owasp.mastestapp.MastgTest$$ExternalSyntheticLambda0
            @Override // java.lang.Runnable
            public final void run() {
                MastgTest.mastgTest$lambda$1(SENSITIVE_DATA, result);
            }
        });
        thread.start();
        thread.join();
        return (String) result.element;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Type inference failed for: r7v10, types: [T, java.lang.String] */
    public static final void mastgTest$lambda$1(Map SENSITIVE_DATA, Ref.ObjectRef result) {
        Intrinsics.checkNotNullParameter(SENSITIVE_DATA, "$SENSITIVE_DATA");
        Intrinsics.checkNotNullParameter(result, "$result");
        try {
            URL url = new URL("https://httpbin.org/post");
            URLConnection openConnection = url.openConnection();
            Intrinsics.checkNotNull(openConnection, "null cannot be cast to non-null type java.net.HttpURLConnection");
            HttpURLConnection httpURLConnection = (HttpURLConnection) openConnection;
            httpURLConnection.setRequestMethod("POST");
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            Collection destination$iv$iv = new ArrayList(SENSITIVE_DATA.size());
            for (Map.Entry item$iv$iv : SENSITIVE_DATA.entrySet()) {
                String key = (String) item$iv$iv.getKey();
                String value = (String) item$iv$iv.getValue();
                destination$iv$iv.add(URLEncoder.encode(key, "UTF-8") + '=' + URLEncoder.encode(value, "UTF-8"));
                url = url;
            }
            String postData = CollectionsKt.joinToString$default((List) destination$iv$iv, "&", null, null, 0, null, null, 62, null);
            BufferedOutputStream outputStream = new BufferedOutputStream(httpURLConnection.getOutputStream());
            BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(outputStream, "UTF-8"));
            bufferedWriter.write(postData);
            bufferedWriter.flush();
            bufferedWriter.close();
            outputStream.close();
            int responseCode = httpURLConnection.getResponseCode();
            if (responseCode == 200) {
                Log.d("HTTP_SUCCESS", "Successfully authenticated.");
            } else {
                Log.e("HTTP_ERROR", "Failed to authenticate. Response code: " + responseCode);
            }
            result.element = responseCode + "\n\n" + postData;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
