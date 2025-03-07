package org.owasp.mastestapp;

import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0006\u0010\u0005\u001a\u00020\u0006J\u000e\u0010\u0007\u001a\u00020\b2\u0006\u0010\u0002\u001a\u00020\u0003J\u0006\u0010\t\u001a\u00020\u0006R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\n"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "checkStrongBiometricStatus", "", "isDeviceSecure", "", "mastgTest", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
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
        String biometricStatus = checkStrongBiometricStatus();
        return "Device has a passcode: " + isLocked + "\n\nBiometric status: " + biometricStatus;
    }

    public final boolean isDeviceSecure(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Object systemService = context.getSystemService("keyguard");
        Intrinsics.checkNotNull(systemService, "null cannot be cast to non-null type android.app.KeyguardManager");
        KeyguardManager keyguardManager = (KeyguardManager) systemService;
        return keyguardManager.isDeviceSecure();
    }

    public final String checkStrongBiometricStatus() {
        if (Build.VERSION.SDK_INT >= 30) {
            BiometricManager biometricManager = (BiometricManager) this.context.getSystemService(BiometricManager.class);
            int result = biometricManager.canAuthenticate(15);
            switch (result) {
                case 0:
                    return "BIOMETRIC_SUCCESS - Strong biometric authentication is available.";
                case 1:
                    return "BIOMETRIC_ERROR_HW_UNAVAILABLE - Biometric hardware is currently unavailable.";
                case 11:
                    return "BIOMETRIC_ERROR_NONE_ENROLLED - No biometrics enrolled.";
                case 12:
                    return "BIOMETRIC_ERROR_NO_HARDWARE - No biometric hardware available.";
                default:
                    return "Unknown biometric status: " + result;
            }
        }
        return "Strong biometric authentication check is not supported on this API level.";
    }
}
