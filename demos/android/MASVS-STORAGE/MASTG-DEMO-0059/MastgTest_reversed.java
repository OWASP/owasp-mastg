package org.owasp.mastestapp;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.HashSet;
import java.util.Set;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\b\u001a\u00020\u0007R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\t"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "sensitiveData", "", "mastgTest", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;
    private final String sensitiveData;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        this.sensitiveData = "These are some strings which are considered sensitive data. They should not be stored insecurely: \nArtifactory: AKCp73pL4kpx91TSG1v2J5sLz6rHbHCVF5S3A\nAWSKey: AKIAIOSFODNN7EXAMPLE\nAzureStorageKey: Eby8vdM02xNO+G6CZDtl/JlEt2k='ExAmPlEkEy\nBasicAuth: dXNlcm5hbWU6cGFzc3dvcmQ=\nCloudant: 4c9d0a20f5-2f52-4be1-9a27-19e40bd2ac83-bluemix\nDiscordBotToken: ODkxMjI2OTg0ODIxNzcyMDY4.YfP-cw.k5FVSFOjVC0GZ6qHwWr2hsU-34U\nGitHubToken: ghp_1234567890abcdefghijklmnOPQRSTUV\nGitLabToken: glpat-12abc34XYZ5efGHIJKL67mnOpQrSt\nBase64HighEntropyString: QWxhZGRpbjpvcGVuIHNlc2FtZQ==\nHexHighEntropyString: 4a1d2c1f9f835c82d15694e445f7cd9f1db7f6a7\nIbmCloudIam: eyJraWQiOiI2Nzg5eCIsImFsZyI6IkhTMjU2In0\nIbmCosHmac: OUnS6XcBYLArEtyHPtH8/Sdgr7EjIUhe7gZtnrZj\nIPPrivate: 192.168.1.1\nIPPrivate: 172.16.4.5.0\nIPPrivate: 10.0.2.5\nIPLocalHost: 127.0.0.1\nJwtToken: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImlhdCI6MTYxNzA1NjgwMCwiZXhwIjoxNjE3MDU3MDAwfQ.sJgFhsr5d2JG1hKOnwzzd8qzNx56Z76pRVKkJVGmPAI\nMailchimp: 9d7c1b4fd8bbddad8ecf841d-us20\nNpm: npm_AZ4D3XFUGYD2HC3YBWLNLFIE\nOpenAI: sk-2t1HcLdKzRrn0pOI5GwIaRn8Z2Xgf9\nPrivateKey: MIIEvAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfX7kbfFv3pc3JjOHQ=\nPypiToken: pypi-AgENdGVzdC10b2tlbi0xMjM0\nSendGrid: SG.dummykey12345Uwv5ecA7QG-3W4dUMG\nSlack: xoxb-123456789012-1234567890123-ABCDEFG12345678\nSoftlayer: abcdefghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890abcdef\nSquareOAuth: sq0atp-1rLNX1q4TaLRcS1Xr1kWlA\nStripe: sk_test_4eC39HqLyjWDarjtT1zdp7dc\nTelegramBotToken: 123456789:AAHojBo45KxlmdmpI3XlVu3iTDnjFPlwd\nTwilioKey: SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nPrivateKey: MIIEvAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfX7kbfFv3pc3JjOHQ=\nPrivateKey: -----BEGIN RSA PRIVATE KEY-----\nPrivateKey: -----BEGIN RSA PRIVATE KEY-----\nPrivateKey: -----BEGIN DSA PRIVATE KEY-----\nPrivateKey: -----BEGIN DSA PUBLIC KEY-----\nPrivateKey: -----BEGIN EC PRIVATE KEY-----\nPrivateKey: -----BEGIN EC PUBLIC KEY-----\nPrivateKey: -----BEGIN DH PARAMETERS-----\nPrivateKey: -----BEGIN PRIVATE KEY-----\nPrivateKey: -----BEGIN EC PRIVATE KEY-----\nPrivateKey: -----BEGIN ENCRYPTED PRIVATE KEY-----\nPrivateKey: -----END RSA PRIVATE KEY-----\nPrivateKey: -----END EC PRIVATE KEY-----\nPrivateKey: Proc-Type: 4,ENCRYPTED\n";
    }

    public final String mastgTest() {
        DemoResults r = new DemoResults("0059");
        try {
            SharedPreferences sharedPref = this.context.getSharedPreferences("MasSharedPref_Sensitive_Data", 0);
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.putString("SensitiveData", this.sensitiveData);
            editor.apply();
            r.add(DemoResults4.FAIL, "Sensitive data has been written to the sandbox using putString().");
            Set stringSet = new HashSet();
            stringSet.add(this.sensitiveData);
            editor.putStringSet("SensitiveDataStringSet", stringSet);
            editor.apply();
            r.add(DemoResults4.FAIL, "Sensitive data has been written to the sandbox using putStringSet().");
        } catch (Exception e) {
            r.add(DemoResults4.ERROR, e.toString());
        }
        return r.toJson();
    }
}