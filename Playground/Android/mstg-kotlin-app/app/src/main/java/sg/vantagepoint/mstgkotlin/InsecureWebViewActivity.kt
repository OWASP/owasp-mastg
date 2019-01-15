package sg.vantagepoint.mstgkotlin

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import kotlinx.android.synthetic.main.activity_insecure_web_view.view.*
import org.jetbrains.anko.find
import org.jetbrains.anko.longToast
import sg.vantagepoint.mstgkotlin.util.JS_Interface

class InsecureWebViewActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_insecure_web_view)

        val file_path = "file:///android_asset/unsafe_content.html"
        val jsInterface = JS_Interface(this)

        val wv_insecureWebView = find<WebView>(R.id.webview_insecure)
        wv_insecureWebView.settings.javaScriptEnabled = true
        wv_insecureWebView.settings.allowFileAccessFromFileURLs = true
        wv_insecureWebView.isVerticalScrollBarEnabled = true
        wv_insecureWebView.isHorizontalScrollBarEnabled = true
        wv_insecureWebView.settings.useWideViewPort = false
        wv_insecureWebView.settings.cacheMode = WebSettings.LOAD_CACHE_ELSE_NETWORK

        wv_insecureWebView.webChromeClient = WebChromeClient()

        // adding the JS interface
        wv_insecureWebView.addJavascriptInterface(jsInterface,"Android")

        // Javascript execution
        wv_insecureWebView.loadUrl(file_path)

        Log.d("Checkpoint-jsEnabled","true")
    }
}
