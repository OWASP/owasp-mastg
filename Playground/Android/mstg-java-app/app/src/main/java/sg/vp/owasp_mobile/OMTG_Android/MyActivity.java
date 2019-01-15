package sg.vp.owasp_mobile.OMTG_Android;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;


public class MyActivity extends AppCompatActivity {

    public final static String EXTRA_MESSAGE = "com.mycompany.myfirstapp.MESSAGE";

    @Override
    protected void onCreate(Bundle savedInstanceState) {


        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_my);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_my, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    /** Called when the user clicks the Send button */
//    public void sendMessage(View view) {
//        Intent intent = new Intent(this, DisplayMessageActivity.class);
//        EditText editText = (EditText) findViewById(R.id.edit_message);
//        String message = editText.getText().toString();
//        intent.putExtra(EXTRA_MESSAGE, message);
//        startActivity(intent);
//    }


    public void OMTG_ENV_005_Webview_Remote(View view) {
        Intent intent = new Intent(this, OMTG_ENV_005_WebView_Remote.class);
        startActivity(intent);
    }


    public void OMTG_ENV_005_Webview_Local(View view) {
        Intent intent = new Intent(this, OMTG_ENV_005_WebView_Local.class);
        startActivity(intent);
    }

    public void OMTG_CODING_003_Best_Practice(View view) {
        Intent intent = new Intent(this, OMTG_CODING_003_Best_Practice.class);
        startActivity(intent);
    }

    public void OMTG_CODING_003_SQL_Injection(View view) {
        Intent intent = new Intent(this, OMTG_CODING_003_SQL_Injection.class);
        startActivity(intent);
    }

    public void OMTG_CODING_003_SQL_Injection_Content_Provider(View view) {
        Intent intent = new Intent(this, OMTG_CODING_003_SQL_Injection_Content_Provider.class);
        startActivity(intent);
    }

    public void OMTG_CODING_004_Code_Injection(View view) {
        Intent intent = new Intent(this, OMTG_CODING_004_Code_Injection.class);
        startActivity(intent);
    }

    public void OMTG_DATAST_001_BadEncryption(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_001_BadEncryption.class);
        startActivity(intent);
    }

    public void OMTG_DATAST_001_KeyChain(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_001_KeyChain.class);
        startActivity(intent);
    }

    public void OMTG_DATAST_001_KeyStore(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_001_KeyStore.class);
        startActivity(intent);
    }

    public void OMTG_DATAST_001_InternalStorage(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_001_InternalStorage.class);
        startActivity(intent);
    }

    public void OMTG_DATAST_001_ExternalStorage(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_001_ExternalStorage.class);
        startActivity(intent);
    }

    public void OMTG_DATAST_001_SharedPreferences(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_001_SharedPreferences.class);
        startActivity(intent);
    }



    public void OMTG_DATAST_001_SQLite_Not_Encrypted(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_001_SQLite_Not_Encrypted.class);
        startActivity(intent);
    }


    public void OMTG_DATAST_001_SQLite_Encrypted(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_001_SQLite_Encrypted.class);
        startActivity(intent);
    }


    public void OMTG_DATAST_002_Logging(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_002_Logging.class);
        startActivity(intent);
    }


    public void OMTG_DATAST_004_3rd_Party(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_004_3rd_Party.class);
        startActivity(intent);
    }


    public void OMTG_DATAST_005_Keyboard_Cache(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_005_Keyboard_Cache.class);
        startActivity(intent);
    }


    public void OMTG_DATAST_006_Clipboard(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_006_Clipboard.class);
        startActivity(intent);
    }

    public void OMTG_DATAST_011_Memory(View view) {
        Intent intent = new Intent(this, OMTG_DATAST_011_Memory.class);
        startActivity(intent);
    }

    public void OMTG_NETW_001_Secure_Channel(View view) {
        Intent intent = new Intent(this, OMTG_NETW_001_Secure_Channel.class);
        startActivity(intent);
    }

    public void OMTG_NETW_004_SSL_Pining(View view) {
        Intent intent = new Intent(this, OMTG_NETW_004_SSL_Pinning.class);
        startActivity(intent);
    }

    public void OMTG_NETW_004_SSL_Pining_Certificate(View view) {
        Intent intent = new Intent(this, OMTG_NETW_004_SSL_Pinning_Certificate.class);
        startActivity(intent);
    }

}
