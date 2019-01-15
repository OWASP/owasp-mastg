package sg.vantagepoint.mstgkotlin.util

import android.content.Context
import android.widget.Toast
import android.webkit.JavascriptInterface

class JS_Interface
/** Instantiate the interface and set the context  */
internal constructor(private var mContext: Context) {

    @JavascriptInterface
    fun returnString(): String {
        return "<strong>This is a Secret String only obtainable via JavaScript</strong>"
    }

    // Show a toast from the web page
    @JavascriptInterface
    fun showToast(toast: String) {
        Toast.makeText(mContext, toast, Toast.LENGTH_LONG).show()
    }
}
