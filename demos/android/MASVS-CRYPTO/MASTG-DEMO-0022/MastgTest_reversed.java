package org.owasp.mastestapp;

import android.content.Context;
import android.util.Base64;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0006\u0010\u0005\u001a\u00020\u0006J\u000e\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\t\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\n\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\u000b\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\f"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "mastgTest", "", "vulnerable3DesEncryption", "data", "vulnerableBlowfishEncryption", "vulnerableDesEncryption", "vulnerableRc4Encryption", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
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
            byte[] keyBytes = new byte[8];
            new SecureRandom().nextBytes(keyBytes);
            DESKeySpec keySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            Key generateSecret = keyFactory.generateSecret(keySpec);
            Intrinsics.checkNotNullExpressionValue(generateSecret, "generateSecret(...)");
            Key secretKey = generateSecret;
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(1, secretKey);
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
            byte[] keyBytes = new byte[24];
            new SecureRandom().nextBytes(keyBytes);
            DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            Key generateSecret = keyFactory.generateSecret(keySpec);
            Intrinsics.checkNotNullExpressionValue(generateSecret, "generateSecret(...)");
            Key secretKey = generateSecret;
            Cipher cipher = Cipher.getInstance("DESede");
            cipher.init(1, secretKey);
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

    public final String vulnerableRc4Encryption(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] keyBytes = new byte[16];
            new SecureRandom().nextBytes(keyBytes);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "RC4");
            Cipher cipher = Cipher.getInstance("RC4");
            cipher.init(1, secretKey);
            byte[] bytes = data.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            byte[] encryptedData = cipher.doFinal(bytes);
            String encodeToString = Base64.encodeToString(encryptedData, 0);
            Intrinsics.checkNotNull(encodeToString);
            return encodeToString;
        } catch (Exception e) {
            return "Encryption error: " + e.getMessage();
        }
    }

    public final String vulnerableBlowfishEncryption(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] keyBytes = new byte[8];
            new SecureRandom().nextBytes(keyBytes);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "Blowfish");
            Cipher cipher = Cipher.getInstance("Blowfish");
            cipher.init(1, secretKey);
            byte[] bytes = data.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            byte[] encryptedData = cipher.doFinal(bytes);
            String encodeToString = Base64.encodeToString(encryptedData, 0);
            Intrinsics.checkNotNull(encodeToString);
            return encodeToString;
        } catch (Exception e) {
            return "Encryption error: " + e.getMessage();
        }
    }

    public final String mastgTest() {
        String desEncryptedString = vulnerableDesEncryption("Hello from the OWASP MASTG Test app.");
        String tripleDesEncryptedString = vulnerable3DesEncryption("Hello from the OWASP MASTG Test app.");
        String rc4EncryptedString = vulnerableRc4Encryption("Hello from the OWASP MASTG Test app.");
        String blowfishEncryptedString = vulnerableBlowfishEncryption("Hello from the OWASP MASTG Test app.");
        return "DES Encrypted: " + desEncryptedString + "\n3DES Encrypted: " + tripleDesEncryptedString + "\nRC4 Encrypted: " + rc4EncryptedString + "\nBlowfish Encrypted: " + blowfishEncryptedString;
    }
}
