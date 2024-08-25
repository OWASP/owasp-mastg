package org.owasp.mastestapp;

import android.content.Context;
import android.util.Base64;
import android.util.Log;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

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
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, new SecureRandom());
        KeyPair keypair = generator.genKeyPair();
        Log.d("Keypair generated RSA", Base64.encodeToString(keypair.getPublic().getEncoded(), 0));
        KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");
        keyGen1.init(128);
        SecretKey secretKey1 = keyGen1.generateKey();
        Intrinsics.checkNotNullExpressionValue(secretKey1, "generateKey(...)");
        KeyGenerator keyGen2 = KeyGenerator.getInstance("AES");
        keyGen2.init(256);
        SecretKey secretKey2 = keyGen2.generateKey();
        Intrinsics.checkNotNullExpressionValue(secretKey2, "generateKey(...)");
        return "Generated RSA Key:\n " + Base64.encodeToString(keypair.getPublic().getEncoded(), 0) + "Generated AES Key1\n " + Base64.encodeToString(secretKey1.getEncoded(), 0) + "Generated AES Key2\n " + Base64.encodeToString(secretKey2.getEncoded(), 0);
    }
}
