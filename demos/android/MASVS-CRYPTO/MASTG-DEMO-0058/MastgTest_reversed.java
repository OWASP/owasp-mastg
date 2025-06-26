package org.owasp.mastestapp;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
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
        DemoResults r = new DemoResults("0058");
        try {
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder("testKeyGenParameter", 1);
            b.setBlockModes("ECB");
            r.add(DemoResults4.FAIL, "The associated key uses the insecure symmetric encryption block mode ECB only.");
            b.setBlockModes("ECB", "CBC");
            r.add(DemoResults4.FAIL, "The associated key may use the insecure symmetric encryption block mode ECB.");
            b.setBlockModes("CBC", "ECB");
            r.add(DemoResults4.FAIL, "The associated key may use the insecure symmetric encryption block mode ECB.");
        } catch (Exception e) {
            r.add(DemoResults4.ERROR, e.toString());
        }
        return r.toJson();
    }
}