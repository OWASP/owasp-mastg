package sg.vp.owasp_mobile.OMTG_Android;

import android.content.Intent;
import android.os.Bundle;
import android.security.KeyChain;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class OMTG_DATAST_001_KeyChain extends AppCompatActivity {

    public static final String PKCS12_FILENAME = "server.p12";

    //private static final String DEFAULT_ALIAS = "My Key Chain";
    //Request code used when starting the activity using the KeyChain install intent
    //private static final int INSTALL_KEYCHAIN_CODE = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__datast_001__key_chain);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        installPkcs12();
    }


    private void installPkcs12() {

        try {
            // debug - filenames in assets directory
            String[] f = getAssets().list("");
            for(String f1 : f){
                Log.v("names",f1);
            }

            BufferedInputStream bis = new BufferedInputStream(getAssets().open(PKCS12_FILENAME));
            byte[] keychain = new byte[bis.available()];
            bis.read(keychain);

            Intent installIntent = KeyChain.createInstallIntent();
            installIntent.putExtra(KeyChain.EXTRA_PKCS12, keychain);
            startActivity(installIntent);
//            installIntent.putExtra(KeyChain.EXTRA_NAME, DEFAULT_ALIAS);
//            startActivityForResult(installIntent, INSTALL_KEYCHAIN_CODE);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


}
