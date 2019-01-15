package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.widget.Button;

public class OMTG_DATAST_004_3rd_Party extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__datast_004__3rd_party);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // find elements
        Button btnCrash = (Button) findViewById(R.id.crashButton);

        // create click listener for crash
        View.OnClickListener oclbtnCrash = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                CrashApp();
            }
        };

        // assign click listener
        btnCrash.setOnClickListener(oclbtnCrash);
    }

    private void CrashApp() {
        throw new RuntimeException("This is a crash");
    }

}
