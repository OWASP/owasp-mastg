package sg.vantagepoint.mstgkotlin

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.webkit.WebSettings
import android.webkit.WebView
import org.jetbrains.anko.find

class SecureWebViewActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_secure_web_view)

        val file_path = "file:///android_asset/unsafe_content.html"

        val wv_secureWebView = find<WebView>(R.id.webview_secure)
        wv_secureWebView.settings.javaScriptEnabled = false
        wv_secureWebView.isVerticalScrollBarEnabled = true
        wv_secureWebView.isHorizontalScrollBarEnabled = true
        wv_secureWebView.settings.useWideViewPort = false
        wv_secureWebView.settings.cacheMode = WebSettings.LOAD_CACHE_ELSE_NETWORK
        wv_secureWebView.loadUrl(file_path)

//        Log.d("Checkpoint-jsEnabled","false")
    }
}
