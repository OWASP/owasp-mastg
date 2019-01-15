package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class OMTG_DATAST_002_Logging extends AppCompatActivity {

    // Tag can be used for logging
    String TAG = "OMTG_DATAST_002_Logging";
    EditText usernameText, passwordText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__datast_002__logging);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // find elements
        usernameText = (EditText) findViewById(R.id.loggingUsername);
        passwordText = (EditText) findViewById(R.id.loggingPassword);
        Button btnLogin = (Button) findViewById(R.id.loginButton);

        // create click listener for login
        View.OnClickListener oclbtnLogin = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                CreateLogs(usernameText.getText().toString(), passwordText.getText().toString());
            }
        };

        // assign click listener to the Decrypt button (btnDecrypt)
        btnLogin.setOnClickListener(oclbtnLogin);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

    }

    private void CreateLogs(String username, String password) {

        // error log
        Log.e(TAG, "User successfully logged in. User: "+username+" Password: "+password);

        System.out.println("WTF, Logging Class should be used instead.");

        Toast.makeText(this, "Log output has been created", Toast.LENGTH_LONG).show();

    }
}
