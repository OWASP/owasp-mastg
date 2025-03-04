package org.owasp.mastestapp;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(m69d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0006\u0010\u0005\u001a\u00020\u0006J\u000e\u0010\u0007\u001a\u00020\b2\u0006\u0010\u0002\u001a\u00020\u0003J\u0006\u0010\t\u001a\u00020\bJ\u0006\u0010\n\u001a\u00020\u000bR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\f"}, m70d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "getSystemSdkVersion", "", "isDeviceSecure", "", "isSystemDebuggable", "mastgTest", "", "app_debug"}, m71k = 1, m72mv = {1, 9, 0}, m74xi = 48)
/* loaded from: classes4.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() {
        boolean isLocked = isDeviceSecure(this.context);
        int androidSdkVersion = getSystemSdkVersion();
        boolean isSystemDebuggable = isSystemDebuggable();
        return "Device has a passcode: " + isLocked + "\nandroidSdkVersion:" + androidSdkVersion + "\nisSystemDebuggable:" + isSystemDebuggable;
    }

    public final boolean isDeviceSecure(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Object systemService = context.getSystemService("keyguard");
        Intrinsics.checkNotNull(systemService, "null cannot be cast to non-null type android.app.KeyguardManager");
        KeyguardManager keyguardManager = (KeyguardManager) systemService;
        return keyguardManager.isDeviceSecure();
    }

    public final int getSystemSdkVersion() {
        return Build.VERSION.SDK_INT;
    }

    public final boolean isSystemDebuggable() {
        return Intrinsics.areEqual(Build.TYPE, "eng") || Intrinsics.areEqual(Build.TYPE, "userdebug");
    }
}
