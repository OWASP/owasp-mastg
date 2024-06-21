package org.owasp.mastestapp;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import kotlin.Metadata;
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
        File externalStorageDir = this.context.getExternalFilesDir(null);
        File fileName = new File(externalStorageDir, "secret.txt");
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
            FileOutputStream output = fileOutputStream;
            byte[] bytes = "secr3tPa$$W0rd\n".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            output.write(bytes);
            Log.d("WriteExternalStorage", "File written to external storage successfully.");
            CloseableKt.closeFinally(fileOutputStream, null);
            return "SUCCESS!!\n\nFile " + fileName + " with content secr3tPa$$W0rd\n saved to " + externalStorageDir;
        } catch (IOException e) {
            Log.e("WriteExternalStorage", "Error writing file to external storage", e);
            return "ERROR!!\n\nError writing file to external storage";
        }
    }
}
