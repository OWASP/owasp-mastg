package sg.vp.owasp_mobile.OMTG_Android;

import android.annotation.TargetApi;
import android.os.Build;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;


import net.sqlcipher.database.SQLiteDatabase;
import java.io.File;


public class OMTG_DATAST_001_SQLite_Encrypted extends AppCompatActivity {

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__datast_001__sqlite__secure);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        SQLiteEnc();
    }


    public native String  stringFromJNI();

    static {
        System.loadLibrary("native");
    }



    private void SQLiteEnc() {
        SQLiteDatabase.loadLibs(this);

        File database = getDatabasePath("encrypted");
        database.mkdirs();
        database.delete();

        SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, stringFromJNI(), null);

        secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
        secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
        secureDB.close();
    }
}