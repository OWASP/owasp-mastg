package sg.vp.owasp_mobile.OMTG_Android;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.support.v7.widget.Toolbar;
import android.webkit.WebView;

public class OMTG_NETW_001_Secure_Channel extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__netw_001__secure__channel);

        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        WebView insecure = (WebView) findViewById(R.id.webView1);
        WebView secure = (WebView) findViewById(R.id.webView2);

        // plane http call
        insecure.loadUrl(getResources().getString(R.string.url_example));

        // secure https call
        secure.loadUrl(getResources().getString(R.string.url_example_ssl));
    }
}
