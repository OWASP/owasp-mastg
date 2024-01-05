public class MainActivity extends AppCompatActivity { 

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // ruleid: MSTG-PLATFORM-6.1    
        WebView webview2 = new WebView(this);
        setContentView(webview2);
        String url = "ftp://127.0.0.1";
        webview2.getSettings().setAllowUniversalAccessFromFileURLs(false);
        webview2.getSettings().setJavaScriptEnabled(true);        
        webview2.getSettings().setAllowFileAccess(false);
        webview2.getSettings().setAllowContentAccess(false);
        webview2.getSettings().setAllowFileAccessFromFileURLs(false);
        webview2.loadUrl(url); 
    }
    
    // ruleid: MSTG-PLATFORM-6.1 
    private class MainActivityWebView extends WebView {  
        protected void test() {        
            String url = "https://://127.0.0.1";
            getSettings().setAllowUniversalAccessFromFileURLs(false);
            getSettings().setJavaScriptEnabled(true);        
            getSettings().setAllowFileAccess(false);
            this.getSettings().setAllowContentAccess(true);
            getSettings().setAllowFileAccessFromFileURLs(false);
            this.loadUrl(url); 
        }
    }

}
