public class MainActivity extends AppCompatActivity {
    WebView webView;
  
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        // ruleid: MSTG-PLATFORM-5
        settings.setJavaScriptEnabled(true);
        setContentView(webView);
        
        WebView webview2 = new WebView(this);
        setContentView(webview2);
        // ruleid: MSTG-PLATFORM-5
        webview2.getSettings().setJavaScriptEnabled(true);
    }
}

