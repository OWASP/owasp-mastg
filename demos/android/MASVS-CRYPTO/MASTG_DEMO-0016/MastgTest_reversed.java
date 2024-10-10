package org.owasp.mastestapp;

import android.content.Context;
import android.util.Base64;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0005\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0006\u0010\u0005\u001a\u00020\u0006J\u000e\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\t\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\n\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000b"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "mastgTest", "", "vulnerable3DesEncryption", "data", "vulnerableAesEcbEncryption", "vulnerableDesEncryption", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
/* loaded from: classes4.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String vulnerableDesEncryption(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] bytes = "12345678".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            DESKeySpec keySpec = new DESKeySpec(bytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            Key generateSecret = keyFactory.generateSecret(keySpec);
            Intrinsics.checkNotNullExpressionValue(generateSecret, "generateSecret(...)");
            Key secretKey = generateSecret;
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(1, secretKey);
            byte[] bytes2 = data.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes2, "this as java.lang.String).getBytes(charset)");
            byte[] encryptedData = cipher.doFinal(bytes2);
            String encodeToString = Base64.encodeToString(encryptedData, 0);
            Intrinsics.checkNotNullExpressionValue(encodeToString, "encodeToString(...)");
            return encodeToString;
        } catch (Exception e) {
            return "Encryption error: " + e.getMessage();
        }
    }

    public final String vulnerableAesEcbEncryption(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] key = "1234567890123456".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(key, "this as java.lang.String).getBytes(charset)");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(1, secretKeySpec);
            byte[] bytes = data.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            byte[] encryptedData = cipher.doFinal(bytes);
            String encodeToString = Base64.encodeToString(encryptedData, 0);
            Intrinsics.checkNotNullExpressionValue(encodeToString, "encodeToString(...)");
            return encodeToString;
        } catch (Exception e) {
            return "Encryption error: " + e.getMessage();
        }
    }

    public final String vulnerable3DesEncryption(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] bytes = "123456789012345678901234".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            DESedeKeySpec keySpec = new DESedeKeySpec(bytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            Key generateSecret = keyFactory.generateSecret(keySpec);
            Intrinsics.checkNotNullExpressionValue(generateSecret, "generateSecret(...)");
            Key secretKey = generateSecret;
            Cipher cipher = Cipher.getInstance("DESede");
            cipher.init(1, secretKey);
            byte[] bytes2 = data.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes2, "this as java.lang.String).getBytes(charset)");
            byte[] encryptedData = cipher.doFinal(bytes2);
            String encodeToString = Base64.encodeToString(encryptedData, 0);
            Intrinsics.checkNotNullExpressionValue(encodeToString, "encodeToString(...)");
            return encodeToString;
        } catch (Exception e) {
            return "Encryption error: " + e.getMessage();
        }
    }

    public final String mastgTest() {
        String desEncryptedString = vulnerableDesEncryption("Hello from the OWASP MASTG Test app.");
        String aesEcbEncryptedString = vulnerableAesEcbEncryption("Hello from the OWASP MASTG Test app.");
        String tripleDesEncryptedString = vulnerable3DesEncryption("Hello from the OWASP MASTG Test app.");
        return "DES Encrypted: " + desEncryptedString + "\nAES ECB Encrypted: " + aesEcbEncryptedString + "\n3DES Encrypted: " + tripleDesEncryptedString;
    }
}
