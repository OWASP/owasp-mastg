package org.owasp.mastestapp;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.os.StrictMode;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\b\u0010\u0005\u001a\u00020\u0006H\u0002J\u0006\u0010\u0007\u001a\u00020\bJ\b\u0010\t\u001a\u00020\u0006H\u0002R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\n"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "enableStrictMode", "", "mastgTest", "", "triggerSqliteCursorLeak", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
/* loaded from: classes4.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() {
        enableStrictMode();
        triggerSqliteCursorLeak();
        System.gc();
        return "SUCCESS!!\n\nSQL Cursor leaked.";
    }

    private final void enableStrictMode() {
        StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().detectLeakedClosableObjects().penaltyLog().build());
    }

    private final void triggerSqliteCursorLeak() {
        SQLiteDatabase db = this.context.openOrCreateDatabase("test.db", 0, null);
        Intrinsics.checkNotNullExpressionValue(db, "openOrCreateDatabase(...)");
        db.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)");
        db.execSQL("INSERT INTO users (name) VALUES ('Alice'), ('Bob')");
        db.rawQuery("SELECT * FROM users", null);
    }
}
