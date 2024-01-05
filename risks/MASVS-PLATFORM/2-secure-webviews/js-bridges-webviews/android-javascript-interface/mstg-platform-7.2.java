public class WebAppInterface {
    Context mContext;
    public void test1(){
        MSTG_ENV_008_JS_Interface jsInterface = new MSTG_ENV_008_JS_Interface(this);
        // ruleid: MSTG-PLATFORM-7.2
        myWebView.addJavascriptInterface(jsInterface, "Android");
    }
}
public class WebAppInterface extends WebView {
    Context mContext;
    public void test2(){
        // ruleid: MSTG-PLATFORM-7.2
        addJavascriptInterface(new MSTG_ENV_008_JS_Interface(this), "Android");
    }
    public void test3(){
        // ruleid: MSTG-PLATFORM-7.2
        this.addJavascriptInterface(new MSTG_ENV_008_JS_Interface(this), "Android");
    }
}
