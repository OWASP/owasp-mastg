public class TestClass {

    protected boolean getBoolean() {
        return false;
    }
  
    protected void test() {        
        WebView webview2 = new WebView(this);
        String url = "ftp://127.0.0.1";
        webview2.getSettings().setAllowUniversalAccessFromFileURLs(false);
        // ruleid: MSTG-PLATFORM-6.2
        webview2.getSettings().setAllowFileAccess(true);
        // ruleid: MSTG-PLATFORM-6.2
        webview2.getSettings().setAllowContentAccess(true);
        // ruleid: MSTG-PLATFORM-6.2
        webview2.getSettings().setAllowFileAccessFromFileURLs(this.getBoolean());
        webview2.loadUrl(url); 
    }

    protected void test2() {        
        WebView webview2 = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        String url = "ftp://127.0.0.1";
        // ok: MSTG-PLATFORM-6.2
        settings.setAllowUniversalAccessFromFileURLs(false);
        // ruleid: MSTG-PLATFORM-6.2
        settings.setAllowFileAccess(true);
        // ruleid: MSTG-PLATFORM-6.2
        settings.setAllowContentAccess(true);
        // ruleid: MSTG-PLATFORM-6.2
        settings.setAllowFileAccessFromFileURLs(this.getBoolean());
        webview2.loadUrl(url); 
    }

    public class WebAppInnnerCalss extends WebView {
        Context mContext;
        public void test4(){
            // ruleid: MSTG-PLATFORM-6.2
            getSettings().setAllowUniversalAccessFromFileURLs(true);     
            // ok: MSTG-PLATFORM-6.2
            getSettings().setAllowFileAccess(false);
            // ruleid: MSTG-PLATFORM-6.2
            getSettings().setAllowContentAccess(true);
            getSettings().setAllowFileAccessFromFileURLs(false);
        }
    }
    
}
