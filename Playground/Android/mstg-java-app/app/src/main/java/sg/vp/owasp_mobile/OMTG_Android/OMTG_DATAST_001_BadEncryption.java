package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;


public class OMTG_DATAST_001_BadEncryption extends AppCompatActivity {

    EditText passwordEditText;
    Button btnVerify;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__datast_001__bad_encryption);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        passwordEditText = (EditText) findViewById(R.id.BadEnryptionPassword);
        btnVerify = (Button) findViewById(R.id.BadEnryptionButton);

        // create click listener for encryption
        View.OnClickListener oclbtnVerify = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                verify(passwordEditText.getText().toString());
                Boolean result = verify(passwordEditText.getText().toString());
                result(result);
            }
        };

        // assign click listener to the Decrypt button (btnDecrypt)
        btnVerify.setOnClickListener(oclbtnVerify);

    }


    private void result(Boolean result) {

        if (result) {
            Toast.makeText(this, "Congratulations, this is the correct password", Toast.LENGTH_LONG).show();
        }
        else {
            Toast.makeText(this, "Try again!", Toast.LENGTH_LONG).show();
        }
    }


    private static boolean verify(String str) {

        // This is the encrypted message
        // decrypted = SuperSecret
        String encrypted = "vJqfip28ioydips=";
        byte[] encryptedDecoded = Base64.decode(encrypted, Base64.DEFAULT);

        byte[] userPass = encrypt(str);

        if (userPass.length != encryptedDecoded.length) {
            return false;
        }
        for (int i = 0; i < userPass.length; i++) {
            if (userPass[i] != encryptedDecoded[i]) {
                return false;
            }
        }
        return true;
    }

    // function used to encrypt a string
    private static byte[] encrypt(String str) {
        byte[] bytes = str.getBytes();
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] ^ 16);
            int curr =  ~bytes[i] & 0xff;
            bytes[i] = (byte) curr;
        }

        return bytes;
    }

}

