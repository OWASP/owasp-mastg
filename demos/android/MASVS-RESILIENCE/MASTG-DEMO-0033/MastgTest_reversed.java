package org.owasp.mastestapp;

import android.content.Context;
import android.util.Log;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collection;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\r\u0010\u0005\u001a\u00020\u0006H\u0000¢\u0006\u0002\b\u0007J\r\u0010\b\u001a\u00020\u0006H\u0000¢\u0006\u0002\b\tJ\b\u0010\n\u001a\u00020\u0006H\u0002J\u0006\u0010\u000b\u001a\u00020\fR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\r"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "checkRootFiles", "", "checkRootFiles$app_debug", "checkSuCommand", "checkSuCommand$app_debug", "checkSuperUserApk", "mastgTest", "", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
/* loaded from: classes4.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() {
        if (checkRootFiles$app_debug() || checkSuperUserApk() || checkSuCommand$app_debug()) {
            return "Device is rooted";
        }
        return "Device is not rooted";
    }

    public final boolean checkRootFiles$app_debug() {
        Iterable rootPaths = CollectionsKt.listOf((Object[]) new String[]{"/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su", "/sbin/su", "/system/sd/xbin/su", "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup", "/system/xbin/mu"});
        Iterable $this$forEach$iv = rootPaths;
        for (Object element$iv : $this$forEach$iv) {
            String path = (String) element$iv;
            if (new File(path).exists()) {
                Log.d("RootCheck", "Found root file: " + path);
            }
        }
        Iterable $this$any$iv = rootPaths;
        if (($this$any$iv instanceof Collection) && ((Collection) $this$any$iv).isEmpty()) {
            return false;
        }
        for (Object element$iv2 : $this$any$iv) {
            if (new File((String) element$iv2).exists()) {
                return true;
            }
        }
        return false;
    }

    private final boolean checkSuperUserApk() {
        File superUserApk = new File("/system/app/Superuser.apk");
        if (superUserApk.exists()) {
            Log.d("RootCheck", "Found Superuser.apk");
        }
        return superUserApk.exists();
    }

    public final boolean checkSuCommand$app_debug() {
        boolean z = false;
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"which", "su"});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String result = reader.readLine();
            if (result != null) {
                Log.d("RootCheck", "su command found at: " + result);
                z = true;
            } else {
                Log.d("RootCheck", "su command not found");
            }
        } catch (IOException e) {
            Log.d("RootCheck", "Error checking su command: " + e.getMessage());
        }
        return z;
    }
}
