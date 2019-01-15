package sg.vp.owasp_mobile.OMTG_Android;

import android.content.Context;
import android.webkit.JavascriptInterface;
import android.widget.Toast;

/**
 * Created by sven on 22/6/16.
 */
public class OMTG_ENV_005_JS_Interface {

        Context mContext;

        /** Instantiate the interface and set the context */
        OMTG_ENV_005_JS_Interface(Context c) {
            mContext = c;
        }

    public OMTG_ENV_005_JS_Interface() {

    }

    @JavascriptInterface
        public String returnString () {
            return "Secret String";
        }

        /** Show a toast from the web page */
        @JavascriptInterface
        public void showToast(String toast) {
            Toast.makeText(mContext, toast, Toast.LENGTH_SHORT).show();
        }
}