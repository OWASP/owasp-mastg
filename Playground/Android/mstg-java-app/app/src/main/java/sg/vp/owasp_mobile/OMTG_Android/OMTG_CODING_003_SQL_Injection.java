package sg.vp.owasp_mobile.OMTG_Android;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;

import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.File;


public class OMTG_CODING_003_SQL_Injection extends AppCompatActivity {

    Boolean login = false;
    EditText usernameText;
    EditText passwordText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        initializeDB(getApplicationContext());

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__coding_003__sql__injection);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // find elements
        usernameText = (EditText) findViewById(R.id.sqlInjectionUsername);
        passwordText = (EditText) findViewById(R.id.sqlInjectionPassword);
        Button btnLogin = (Button) findViewById(R.id.sqlInjectionButton);

        // create click listener for login
        View.OnClickListener oclbtnLogin = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                login = checkLogin(usernameText.getText().toString(), passwordText.getText().toString());
                toastOutput(login);
            }


        };

        // assign click listener to the Decrypt button (btnDecrypt)
        btnLogin.setOnClickListener(oclbtnLogin);

    }

    private void toastOutput(Boolean login) {
        if (login) {
            Toast.makeText(this, "User logged in", Toast.LENGTH_LONG).show();
        } else {
            Toast.makeText(this, "Username and/or password wrong", Toast.LENGTH_LONG).show();
        }
    }

    private void initializeDB(Context applicationContext) {

        File dbAvailable;

        dbAvailable = applicationContext.getDatabasePath("authentication");

        if (!dbAvailable.exists()) {
            SQLiteDatabase authentication = openOrCreateDatabase("authentication", MODE_PRIVATE, null);

            authentication.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
            authentication.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
            authentication.close();
        }
    }


    // Code Snippet from Bulletproof Android, Page 128
    private boolean checkLogin(String username, String password) {
        boolean bool = false;
        SQLiteDatabase authentication = openOrCreateDatabase("authentication", MODE_PRIVATE, null);
        try (Cursor cursor = authentication.rawQuery("SELECT * FROM Accounts WHERE Username = '" + username + "' and Password = '" + password + "';", null)) {
            if (cursor != null) {
                if (cursor.moveToFirst())
                    bool = true;
                cursor.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bool;
    }

}
