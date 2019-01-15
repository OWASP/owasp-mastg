package sg.vp.owasp_mobile.OMTG_Android;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.widget.Button;

public class OMTG_ENV_005_WebView_Local extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_omtg__env_005__web_view__local);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        final Button button = (Button) findViewById(R.id.button2);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                // Perform action on click
                WebView myWebView = (WebView) findViewById(R.id.webView2);
                myWebView.reload();
            }
        });

        WebView myWebView = (WebView) findViewById(R.id.webView2);

        myWebView.getSettings().setJavaScriptEnabled(true);

        myWebView.getSettings().setAllowFileAccessFromFileURLs(true);

        myWebView.setWebChromeClient(new WebChromeClient());

        myWebView.addJavascriptInterface(new JavaScriptInterface(), "jsinterface");
//        OMTG_ENV_005_JS_Interface jsInterface = new OMTG_ENV_005_JS_Interface(this);
//        myWebView.addJavascriptInterface(jsInterface, "Android");

        myWebView.loadUrl("file:///android_asset/local.htm");

//        setContentView(myWebView);
    }

    final class JavaScriptInterface {
        JavaScriptInterface () { }

        @JavascriptInterface
        public String getSomeString() {
            return "string";
        }
    }

}
