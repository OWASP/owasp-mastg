package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Button;


// Project from jduck, https://github.com/jduck/VulnWebView/
public class OMTG_ENV_005_WebView_Remote extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__env_005__web_view);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        final Button button = (Button) findViewById(R.id.button1);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                // Perform action on click
                WebView myWebView = (WebView) findViewById(R.id.webView1);
                myWebView.reload();
            }
        });

        WebView myWebView = (WebView) findViewById(R.id.webView1);

        myWebView.setWebChromeClient(new WebChromeClient());

        // not a good idea!
        WebSettings webSettings = myWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);

        OMTG_ENV_005_JS_Interface jsInterface = new OMTG_ENV_005_JS_Interface(this);

        // terrible idea!
        myWebView.addJavascriptInterface(jsInterface, "Android");

        // woot.
        myWebView.loadUrl("https://rawgit.com/sushi2k/AndroidWebView/master/webview.htm");
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_my, menu);
        return true;
    }

}