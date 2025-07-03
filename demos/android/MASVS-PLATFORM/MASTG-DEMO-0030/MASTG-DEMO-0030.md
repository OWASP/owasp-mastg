---
platform: android
title: Uses of WebViews Allowing Content Access with Frida
id: MASTG-DEMO-0030
code: [kotlin]
test: MASTG-TEST-0251
---

## Sample

This sample demonstrates the use of WebViews allowing content access in an Android app and how an attacker could exploit these settings to exfiltrate sensitive data from the app's internal storage using content URIs.

{{ AndroidManifest.xml # filepaths.xml # MastgTestWebView.kt }}

### AndroidManifest.xml

The app declares a content provider in the `AndroidManifest.xml` file, specifically a `FileProvider` with access to the app's internal storage as specified in the `filepaths.xml` file.

Note that for the exfiltration to work we include the `android:usesCleartextTraffic="true"` attribute in the `AndroidManifest.xml` file to allow cleartext traffic. However, the same script would work with HTTPS endpoints.

### MastgTestWebView.kt

The code includes a script that demonstrates how an attacker could exploit the WebView settings to exfiltrate sensitive data **from the app's internal storage** using content URIs (`content://`).

This sample:

- writes a sensitive file (`api-key.txt`) into internal storage using `File.writeText()`.
- configures a WebView to
    - allow JavaScript execution (`javaScriptEnabled = true`).
    - allow universal access from file URLs (`allowUniversalAccessFromFileURLs = true`). Otherwise, the `XMLHttpRequest` to a `content://` URI from a `file://` base URL would be blocked due to CORS policy.
    - content access is allowed by default (not explicitly called).
- to simulate an XSS attack, the WebView uses `loadDataWithBaseURL` to load an HTML page with embedded JavaScript controlled by the attacker.

### HTML and JavaScript

See `vulnerableHtml` in the MastgTestWebView.kt file.

1. The attacker's script (running in the context of the vulnerable page) uses `XMLHttpRequest` to load the sensitive file from the content provider. The file is located at `/data/data/org.owasp.mastestapp/files/api-key.txt`
2. `fetch` is used to send the file contents to an external server running on the host machine while the app is executed in the Android emulator (`http://10.0.2.2:5001/receive`).

**Note:** For demonstration purposes, the exfiltrated data is displayed on screen. However, in a real attack scenario, the user would not notice as the data would be exfiltrated silently.

### server.py

A simple Python server that listens for incoming requests on port 5001 and logs the received data.

{{ server.py }}

## Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C` and/or `q` to quit the Frida CLI

{{ run.sh # script.js }}

The Frida script is designed to enumerate instances of `WebView` in the application and list their configuration values. The script does not explicitly hook the setters of the `WebView` settings but instead calls the `getSettings()` method to retrieve the current configuration.

The script performs the following steps:

1. Enumerates all instances of `WebView` in the application.
2. For each `WebView` instance, it calls the `getSettings()` method to retrieve the current settings.
3. Prints the configuration values of the `WebView` settings.
4. Prints a backtrace when the `getSettings()` method is called to help identify where in the code the settings are being accessed.

## Observation

The output shows that Frida found one WebView instance and lists many of the WebView settings. A backtrace is also provided to help identify where in the code the settings are being accessed.

{{ output.txt }}

We can also see how the sensitive data was exfiltrated to the attacker's server by inspecting the server logs.

{{ output_server.txt }}

## Evaluation

The test **fails** due to the following WebView settings being configured:

{{ evaluation.txt }}

Note that the method `setAllowContentAccess` is not explicitly called in the code. However, using this approach we can't really tell since we're inspecting the WebView settings after they have been configured.

As indicated by the backtrace in the output, the settings were called in the `mastgTest` method of the `MastgTestWebView` class. Since this app is a demo and code obfuscation tools like ProGuard or R8 are not applied, we can even see the exact file name and line number where the settings were configured: `MastgTestWebView.kt:25`. In a production build, this information is typically removed or obfuscated unless explicitly preserved.
