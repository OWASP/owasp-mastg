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

public class OMTG_CODING_003_Best_Practice extends AppCompatActivity {

    Boolean login = false;
    EditText usernameText;
    EditText passwordText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        initializeDB(getApplicationContext());

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__coding_003__best__practice);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // find elements
        usernameText = (EditText) findViewById(R.id.sqlInjectionBestPracticeUsername);
        passwordText = (EditText) findViewById(R.id.sqlInjectionBestPracticePassword);
        Button btnLogin = (Button) findViewById(R.id.sqlInjectionBestPracticeButton);

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

        dbAvailable = applicationContext.getDatabasePath("authentication-best-practice");

        if (!dbAvailable.exists()) {
            SQLiteDatabase authentication = openOrCreateDatabase("authentication-best-practice", MODE_PRIVATE, null);

            authentication.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
            authentication.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
            authentication.close();
        }
    }


    private boolean checkLogin(String username, String password) {
        boolean bool = false;
        SQLiteDatabase authentication = openOrCreateDatabase("authentication-best-practice", MODE_PRIVATE, null);

// Not Possible to get a cursor back when using SQLite Statement
//        String sql = "SELECT * FROM Accounts WHERE Username = ? and Password = ?";
//        authentication.beginTransactionNonExclusive();

//        try {
//            SQLiteStatement stmt = authentication.compileStatement(sql);
//            stmt.bindString(1,username);
//            stmt.bindString(2,password);
//            stmt.execute();
//            stmt.clearBindings();
//            authentication.setTransactionSuccessful();
//        }
//        finally {
//            authentication.endTransaction();
//            authentication.close();
//        }


        try (Cursor cursor = authentication.rawQuery("SELECT * FROM Accounts WHERE Username=? and Password=?", new String[] {username,password})) {
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
