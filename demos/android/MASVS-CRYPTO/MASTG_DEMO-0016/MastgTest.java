package org.owasp.mastestapp;

import android.content.Context;
import android.util.Base64;
import java.security.Key;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\b\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0006\u0010\u0005\u001a\u00020\u0006J\u000e\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\t\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\n\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\u000b\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\f\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006J\u000e\u0010\r\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0006R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000e"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "mastgTest", "", "vulnerable3DesEcbPkcs5Padding", "data", "vulnerableAesEcbIso10126Padding", "vulnerableAesEcbNoPadding", "vulnerableAesEcbPkcs5Padding", "vulnerableAesEncryption", "vulnerableDesEcbPkcs5Padding", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
/* loaded from: classes4.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String vulnerableAesEncryption(String data) {
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

    public final String vulnerableAesEcbNoPadding(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] key = "1234567890123456".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(key, "this as java.lang.String).getBytes(charset)");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(1, secretKeySpec);
            int paddingLength = 16 - (data.length() % 16);
            String paddedData = data + StringsKt.repeat("\u0000", paddingLength);
            byte[] bytes = paddedData.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            byte[] encryptedData = cipher.doFinal(bytes);
            String encodeToString = Base64.encodeToString(encryptedData, 0);
            Intrinsics.checkNotNullExpressionValue(encodeToString, "encodeToString(...)");
            return StringsKt.trim((CharSequence) encodeToString).toString();
        } catch (Exception e) {
            return "Encryption error: " + e.getMessage();
        }
    }

    public final String vulnerableAesEcbPkcs5Padding(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] key = "1234567890123456".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(key, "this as java.lang.String).getBytes(charset)");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
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

    public final String vulnerableAesEcbIso10126Padding(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] key = "1234567890123456".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(key, "this as java.lang.String).getBytes(charset)");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/ISO10126Padding");
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

    public final String vulnerableDesEcbPkcs5Padding(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] bytes = "12345678".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            DESKeySpec keySpec = new DESKeySpec(bytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            Key generateSecret = keyFactory.generateSecret(keySpec);
            Intrinsics.checkNotNullExpressionValue(generateSecret, "generateSecret(...)");
            Key secretKey = generateSecret;
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
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

    public final String vulnerable3DesEcbPkcs5Padding(String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            byte[] bytes = "123456789012345678901234".getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            DESedeKeySpec keySpec = new DESedeKeySpec(bytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            Key generateSecret = keyFactory.generateSecret(keySpec);
            Intrinsics.checkNotNullExpressionValue(generateSecret, "generateSecret(...)");
            Key secretKey = generateSecret;
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
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
        List results = CollectionsKt.listOf((Object[]) new String[]{"AES Default: " + vulnerableAesEncryption("Hello from OWASP MASTG!"), "AES ECB NoPadding: " + vulnerableAesEcbNoPadding("Hello from OWASP MASTG!"), "AES ECB PKCS5Padding: " + vulnerableAesEcbPkcs5Padding("Hello from OWASP MASTG!"), "AES ECB ISO10126Padding: " + vulnerableAesEcbIso10126Padding("Hello from OWASP MASTG!"), "DES ECB PKCS5Padding: " + vulnerableDesEcbPkcs5Padding("Hello from OWASP MASTG!"), "3DES ECB PKCS5Padding: " + vulnerable3DesEcbPkcs5Padding("Hello from OWASP MASTG!")});
        return CollectionsKt.joinToString$default(results, "\n", null, null, 0, null, null, 62, null);
    }
}
