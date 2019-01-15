package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;

import com.tozny.crypto.android.AesCbcWithIntegrity;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

public class OMTG_DATAST_011_Memory extends AppCompatActivity {

    // Tag can be used for logging
    String TAG = "OMTG_DATAST_011_Memory";
    String plainText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__datast_011__memory);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        decryptString();
    }


    // Using Java-AES-Crypto, https://github.com/tozny/java-aes-crypto
    public void decryptString() {
        // BTW: Really bad idea, as this is the raw private key. Should be stored in the keystore
        String rawKeys = "4zInk+d4jlQ3m1B1ELctxg==:4aZtzwpbniebvM7yC4/GIa2ZmJpSzqrAFtVk91Rm+Q4=";
        AesCbcWithIntegrity.SecretKeys privateKey = null;
        try {
            privateKey = AesCbcWithIntegrity.keys(rawKeys);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        String cipherTextString = "6WpfZkgKMJsPhHNhWoSpVg==:6/TgUCXrAuAa2lUMPWhx8hHOWjWEHFp3VIsz3Ws37ZU=:C0mWyNQjcf6n7eBSFzmkXqxdu55CjUOIc5qFw02aVIfQ1CI8axsHijTJ9ZW6ZfEE";

        AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = new AesCbcWithIntegrity.CipherTextIvMac(cipherTextString);
        try {
            plainText = AesCbcWithIntegrity.decryptString(cipherTextIvMac, privateKey);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

    }

}


