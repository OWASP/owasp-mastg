package org.owasp.mastestapp;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;
import java.io.OutputStream;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.io.CloseableKt;
import kotlin.jvm.internal.Intrinsics;
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
        try {
            ContentResolver resolver = this.context.getContentResolver();
            ContentValues contentValues = new ContentValues();
            contentValues.put("_display_name", "secretFile.txt");
            contentValues.put("mime_type", "text/plain");
            contentValues.put("relative_path", Environment.DIRECTORY_DOCUMENTS);
            Uri textUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);
            if (textUri != null) {
                OutputStream outputStream = resolver.openOutputStream(textUri);
                if (outputStream != null) {
                    OutputStream outputStream2 = outputStream;
                    OutputStream it = outputStream2;
                    byte[] bytes = "MAS_API_KEY=8767086b9f6f976g-a8df76\n".getBytes(Charsets.UTF_8);
                    Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
                    it.write(bytes);
                    it.flush();
                    Unit unit = Unit.INSTANCE;
                    CloseableKt.closeFinally(outputStream2, null);
                }
                Log.d("MediaStore", "File written to external storage successfully.");
                return "SUCCESS!!\n\nMediaStore inserted to " + textUri;
            }
            MastgTest mastgTest = this;
            Log.e("MediaStore", "Error inserting URI to MediaStore.");
            return "FAILURE!!\n\nMediaStore couldn't insert data.";
        } catch (Exception exception) {
            Log.e("MediaStore", "Error writing file to URI from MediaStore", exception);
            return "FAILURE!!\n\nMediaStore couldn't insert data.";
        }
    }
}
