---
masvs_v1_id:
- MSTG-PLATFORM-7
masvs_v2_id:
- MASVS-PLATFORM-2
platform: android
title: Testing for Java Objects Exposed Through WebViews
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

To test for [Java objects exposed through WebViews](../../../Document/0x05h-Testing-Platform-Interaction.md#java-objects-exposed-through-webviews "Java Objects Exposed Through WebViews") check the app for WebViews having JavaScript enabled and determine whether the WebView is creating any JavaScript interfaces aka. "JavaScript Bridges". Finally, check whether an attacker could potentially inject malicious JavaScript code.

## Static Analysis

The following example shows how `addJavascriptInterface` is used to bridge a Java Object and JavaScript in a WebView:

```java
WebView webview = new WebView(this);
WebSettings webSettings = webview.getSettings();
webSettings.setJavaScriptEnabled(true);

MSTG_ENV_008_JS_Interface jsInterface = new MSTG_ENV_008_JS_Interface(this);

myWebView.addJavascriptInterface(jsInterface, "Android");
myWebView.loadURL("http://example.com/file.html");
setContentView(myWebView);
```

In Android 4.2 (API level 17) and above, an annotation `@JavascriptInterface` explicitly allows JavaScript to access a Java method.

```java
public class MSTG_ENV_008_JS_Interface {

        Context mContext;

        /** Instantiate the interface and set the context */
        MSTG_ENV_005_JS_Interface(Context c) {
            mContext = c;
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
```

This is how you can call the method `returnString` from JavaScript, the string "Secret String" will be stored in the variable `result`:

```javascript
var result = window.Android.returnString();
```

With access to the JavaScript code, via, for example, stored XSS or a MITM attack, an attacker can directly call the exposed Java methods.

If `addJavascriptInterface` is necessary, take the following considerations:

- Only JavaScript provided with the APK should be allowed to use the bridges, e.g. by verifying the URL on each bridged Java method (via `WebView.getUrl`).
- No JavaScript should be loaded from remote endpoints, e.g. by keeping page navigation within the app's domains and opening all other domains on the default browser (e.g. Chrome, Firefox).
- If necessary for legacy reasons (e.g. having to support older devices), at least set the minimal API level to 17 in the manifest file of the app (`<uses-sdk android:minSdkVersion="17" />`).

## Dynamic Analysis

Dynamic analysis of the app can show you which HTML or JavaScript files are loaded and which vulnerabilities are present. The procedure for exploiting the vulnerability starts with producing a JavaScript payload and injecting it into the file that the app is requesting. The injection can be accomplished via a MITM attack or direct modification of the file if it is stored in external storage. The whole process can be accomplished via Drozer and weasel (MWR's advanced exploitation payload), which can install a full agent, injecting a limited agent into a running process or connecting a reverse shell as a Remote Access Tool (RAT).

A full description of the attack is included in the blog article ["WebView addJavascriptInterface Remote Code Execution"](https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution/ "WebView addJavascriptInterface Remote Code Execution").
