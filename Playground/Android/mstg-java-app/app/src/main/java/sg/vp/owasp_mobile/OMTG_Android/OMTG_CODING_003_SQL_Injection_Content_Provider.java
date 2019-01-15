package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.net.Uri;
import android.content.ContentValues;
import android.database.Cursor;
import android.widget.EditText;
import android.widget.Toast;


public class OMTG_CODING_003_SQL_Injection_Content_Provider extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__coding_003__sql__injection__content__provider);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_my, menu);
        return true;
    }


    public void onClickAddName(View view) {
        // Add a new student record
        ContentValues values = new ContentValues();

        values.put(OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.NAME,
                ((EditText)findViewById(R.id.editText2)).getText().toString());

        values.put(OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.GRADE,
                ((EditText)findViewById(R.id.editText3)).getText().toString());

        Uri uri = getContentResolver().insert(
                OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.CONTENT_URI, values);

        Toast.makeText(getBaseContext(),
                uri.toString(), Toast.LENGTH_LONG).show();
    }

    public void onClickRetrieveStudents(View view) {

        // Retrieve student records
        String URL = "content://sg.vp.owasp_mobile.provider.College/students";

        EditText searchPattern = (EditText) findViewById(R.id.searchPattern);

        // SQL Injecdtion possible
        // BOB') OR 1=1--
        Log.e("searchPattern", searchPattern.getText().toString());

        String WHERE = null;

        if (searchPattern.getText().toString() != null && !searchPattern.getText().toString().isEmpty()) {
            WHERE = "name='" + searchPattern.getText().toString() + "'";
        }

        Uri students = Uri.parse(URL);
        Cursor c = managedQuery(students, null, WHERE, null, "name");

        if (c.moveToFirst()) {
            do{
                Toast.makeText(this,
                        c.getString(c.getColumnIndex(OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation._ID)) +
                                ", " +  c.getString(c.getColumnIndex( OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.NAME)) +
                                ", " + c.getString(c.getColumnIndex( OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.GRADE)),
                        Toast.LENGTH_SHORT).show();
            } while (c.moveToNext());
        }
    }

}
