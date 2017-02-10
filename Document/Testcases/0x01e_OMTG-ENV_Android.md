### OMTG-ENV-001: Test of App permissions

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]


##### With Source Code

Permissions should be checked if they are really need within the App. For example in order for an Activity to load a web page into a WebView the INTERNET permission in the Android Manifest file is needed.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```



##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link

##### OWASP MASVS

- V6.1: "The app only requires the minimum set of permissions necessary."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link


### OMTG-ENV-002: Test validation and sanitization of input

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link


### OMTG-ENV-003: Test usage of custom URL schemes

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link

##### OWASP MASVS

- V6.3: "The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link


### OMTG-ENV-004: Test for export of sensitive functionality through IPC

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link

##### OWASP MASVS

- V6.4: "The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link



### OMTG-ENV-005: Test for usage of JavaScript in WebViews

#### Overview

In Web applications JavaScript can be injected in many ways by leveraging reflected, stored or DOM based Cross-Site Scripting (XSS). Mobile Apps are executed in a sandboxed environment and when implemented natively do not possess this attack vector. Nevertheless WebViews can be part of a native App to allow viewing of web pages. Every App has it's own cache for WebViews and doesn't share it with the native Browser or other Apps. WebViews in Android are using the WebKit rendering engine to display web pages but are stripped down to a minimum of functions, as for example no address bar is available. If the WebView is implemented too lax and allows the usage of JavaScript it can be used to to attack the App and gain access to it's data.

#### Static Analysis

##### With Source Code

To create and use a WebView, an instance of the class WebView need to be created.

```Java
WebView webview = new WebView(this);
setContentView(webview);
webview.loadUrl("http://slashdot.org/");
```

Different settings can be applied to the WebView of which one is able to activate and deactivate JavaScript. By default JavaScript is disabled in a WebView, so it need to be explicitly enabled. Look for the method setJavaScriptEnabled to check if JavaScript is activated.

```Java
webview.getSettings().setJavaScriptEnabled(true);
```

This allows the WebView to interpret JavaScript and execute it's command.


##### Without Source Code

**...TODO...**

#### Dynamic Analysis

A Dynamic Analysis depends on different surrounding conditions, as there are different possibilities to inject JavaScript into a WebView of an App:
* Stored Cross-Site Scripting (XSS) vulnerability in an endpoint, where the exploit will be sent to the WebView of the Mobile App when navigating to the vulnerable function.
* Man-in-the-middle (MITM) position by an attacker where he is able to tamper the response by injecting JavaScript.
* Malware tampering local files that are loaded by the WebView.

In order to address these attack vectors, the outcome of the following checks should be verified:
* All functions offered by the endpoint need to be free of stored XSS<sup>[4]</sup>.
* The HTTPS communication need to be implemented according to best practices to avoid MITM attacks. This means:
  * whole communication is encrypted via TLS (see OMTG-NET-001),
  * the certificate is checked properly (see OMTG-NET-002) and/or
  * the certificate is even pinned (see OMTG-NET-004)
* Only files within the App data directory should be rendered in a WebView (see OMTG-ENV-007).

#### Remediation

JavaScript is disabled by default in a WebView and if not needed shouldn't be enabled. This reduces the attack surface and potential threats to the App. If JavaScript is needed it should be ensured:
* that the communication relies consistently on HTTPS (see also OMTG-NET-001) to protect the HTML and JavaScript from tampering while in transit.
* that JavaScript and HTML is only loaded locally from within the App data directory or from trusted web servers.

The cache of the WebView should also be cleared in order to remove all JavaScript and locally stored data, by using clearCache()<sup>[2]</sup> when closing the App.

Devices running platforms older than Android 4.4 (API level 19) use a version of Webkit that has a number of security issues. As a workaround, if your app is running on these devices, it must confirm that WebView objects display only trusted content<sup>[3]</sup>.

#### References

##### OWASP Mobile Top 10 2014

* M7 - Client Side Injection

##### OWASP MASVS

- V6.5: "JavaScript is disabled in WebViews unless explicitly required."

##### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html

##### Info

- [1] setJavaScriptEnabled in WebViews  - https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled(boolean)
- [2] clearCache() in WebViews - https://developer.android.com/reference/android/webkit/WebView.html#clearCache(boolean)
- [3] WebView Best Practices - https://developer.android.com/training/articles/security-tips.html#WebView
- [4] Stored Cross-Site Scripting - https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002)

##### Tools

* Tool - Link



### OMTG-ENV-006: Test for protocol handlers in WebViews

#### Overview

Several schemas are available by default in an URI on Android and can be triggered within a WebView<sup>[3]</sup>, e.g:

* http(s):
* file:
* tel:
* geo:

When using them in a link the App can be triggered for example to access a local file when using `file:///storage/emulated/0/private.xml`. This can be exploited by an attacker if he is able to inject JavaScript into the Webview to access local ressources via the file schema.
**..TODO..**

#### Static Analysis

##### With Source Code

The following methods are available for WebViews to control access to different ressources<sup>[4]</sup>:

* setAllowContentAccess(): Content URL access allows WebView to load content from a content provider installed in the system. The default is enabled.
* setAllowFileAccess(): Enables or disables file access within WebView. File access is enabled by default.
* setAllowFileAccessFromFileURLs(): Sets whether JavaScript running in the context of a file scheme URL should be allowed to access content from other file scheme URLs. The default value is true for API level ICE_CREAM_SANDWICH_MR1 and below, and false for API level JELLY_BEAN and above.
* setAllowUniversalAccessFromFileURLs(): Sets whether JavaScript running in the context of a file scheme URL should be allowed to access content from any origin. The default value is true for API level ICE_CREAM_SANDWICH_MR1 and below, and false for API level JELLY_BEAN and above.

If one or all of the methods above can be identified and they are activated it should be verified if it is really needed for the App to work properly.

##### Without Source Code

**..TODO..**

#### Dynamic Analysis

While using the App look for ways to trigger phone calls or accessing files from the file system to identify usage of protocol handlers.
**..TODO..**

#### Remediation

Set the following best practices in order to deactivate protocol handlers, if applicable<sup>[2]</sup>:

```java
//Should an attacker somehow find themselves in a position to inject script into a WebView, then they could exploit the opportunity to access local resources. This can be somewhat prevented by disabling local file system access. It is enabled by default. The Android WebSettings class can be used to disable local file system access via the public method setAllowFileAccess.
webView.getSettings().setAllowFileAccess(false);

webView.getSettings().setAllowFileAccessFromFileURLs(false);

webView.getSettings().setAllowUniversalAccessFromFileURLs(false);

webView.getSettings().setAllowContentAccess(false);
```

Access to files in the file system can be enabled and disabled for a WebView with setAllowFileAccess(). File access is enabled by default and should be deactivated if not needed. Note that this enables or disables file system access only. Assets and resources are still accessible using file:///android_asset and file:///android_res<sup>[1]</sup>.

**..TODO.. How to disable tel and geo schema?**

#### References

##### OWASP Mobile Top 10 2014

* M7 - Client Side Injection

##### OWASP MASVS

- V6.6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."

##### CWE

- CWE-XXX - Title

##### Info

- [1] File Access in WebView - https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess%28boolean%29
- [2] WebView best practices - https://github.com/nowsecure/secure-mobile-development/blob/master/en/android/webview-best-practices.md#remediation
- [3] Intent List - https://developer.android.com/guide/appendix/g-app-intents.html
- [4] WebView Settings - https://developer.android.com/reference/android/webkit/WebSettings.html


##### Tools

* Tool - Link



### OMTG-ENV-007: Test for user supplied local resources in WebViews

#### Overview

WebViews can load content remotely, but can also load it locally from the App data directory or external storage. If the content is loaded locally it should not be possible by the user to influence the filename or path where the file is loaded from or should be able to edit the loaded file.
**..TODO..**

#### Static Analysis

##### With Source Code

Check the source code for the usage of WebViews. If a WebView instance can be identified check if local files are loaded through the method loadURL()<sup>[1]</sup>.

```Java
WebView webview = new WebView(this);
webView.loadUrl("file:///android_asset/filename.html");
```

It need to be verified where the HTML file is loaded from. For example if it's loaded from the external storage the file is read and writeable by everybody and considered a bad practice.

```java
webview.loadUrl("file:///" +
Environment.getExternalStorageDirectory().getPath() +
"filename.html");
```

The URL specified in loadURL() should be checked, if any dynamic parameters are used that can be manipulated, which may lead to local file inclusion.


##### Without Source Code

**..TODO..**

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]
**..TODO..**

#### Remediation

Create a whitelist that defines the web pages and it's protocols (HTTP or HTTPS) that are allowed to be loaded locally and remotely. Loading web pages from the external storage should be avoided as they are read and writable for all users in Android. Instead they should be placed in the assets directory of the App.

Create checksums of the local HTML/JavaScript files and check it during start up of the App. Minify JavaScript files in order to make it harder to read them.

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link

##### OWASP MASVS

- V6.7: "The app does not load user-supplied local resources into WebViews."

##### CWE

- CWE-XXX - Title

##### Info

- [1] loadURL() in WebView - https://developer.android.com/reference/android/webkit/WebView.html#loadUrl(java.lang.String)


##### Tools

* Tool - Link


### OMTG-ENV-008: Test for exposed Java Objects in WebViews

#### Overview

Android offers two different ways that enables JavaScript, executed  in a WebView, to call and use native functions within an Android App:

* `shouldOverrideUrlLoading()`<sup>[4]</sup>
* `addJavascriptInterface()`<sup>[5]</sup>

**shouldOverrideUrlLoading**

This method gives the host application a chance to take over the control when a new url is about to be loaded in the current WebView.  The method shouldOverrideUrlLoading() is available with two different method signatures:

* boolean shouldOverrideUrlLoading (WebView view, String url)
  * This method was deprecated in API level 24.
* boolean shouldOverrideUrlLoading (WebView view, WebResourceRequest request)
  * This method was added in API level 24

**addJavascriptInterface**

The `addJavascriptInterface()` method allows to expose Java Objects to WebViews. When using this method in an Android App it is possible for JavaScript code in a WebView to invoke native methods of the Android App.

Before Android 4.2 JELLY_BEAN (API Level 17) a vulnerability was discovered in the implementation of addJavascriptInterface(), by using reflection that leads to remote code execution when injecting malicious JavaScript in a WebView<sup>[2]</sup>.

With API Level 17 this vulnerability was fixed and the access granted to methods of a Java Object for JavaScript was changed. When using addJavascriptInterface(), methods of a Java Object are only accessible for JavaScript when the annotation `@JavascriptInterface` is explicitly added. Before API Level 17 all methods of the Java Object were accessible by default.

An App that is targeting an Android version before Android 4.2 is still vulnerable to the identified flaw in addJavascriptInterface() and should only be used with extreme care. Therefore several best practices should be applied in case this method is needed.


#### Static Analysis

##### With Source Code

**shouldOverrideUrlLoading**

It need to be verified if and how the method `shouldOverrideUrlLoading()` is used and if it's possible for an attacker to inject malicious JavaScript.

The following example illustrates how the method can be used.

```Java
@Override
public boolean shouldOverrideUrlLoading (WebView view, WebResourceRequest request) {
    URL url = new URL(request.getUrl().toString());
    // execute functions according to values in URL
  }
}
```

If an attacker has access to the JavaScript code, through for example stored XSS or a MITM position he can directly trigger native functions if the exposed Java methods are implemented in an insecure way.

```javascript
window.location = http://example.com/method?parameter=value
```


**addJavascriptInterface**

It need to be verified if and how the method `addJavascriptInterface()` is used and if it's possible for an attacker to inject malicious JavaScript.

The following example shows how addJavascriptInterface is used in a WebView to bridge a Java Object to JavaScript:

```Java
WebView webview = new WebView(this);
WebSettings webSettings = webview.getSettings();
webSettings.setJavaScriptEnabled(true);

MSTG_ENV_008_JS_Interface jsInterface = new MSTG_ENV_008_JS_Interface(this);

myWebView.addJavascriptInterface(jsInterface, "Android");
myWebView.loadURL("http://example.com/file.html");
setContentView(myWebView);
```

In Android API level 17 and above a special annotation is used to explicitly allow the access from JavaScript to a Java method.


```Java
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

If the annotation `@JavascriptInterface` is used, this method can be called from JavaScript. If the App is targeting API level < 17 then all methods of the Java Object are exposed to JavaScript and can be called.

In JavaScript the method `returnString()` can now be called and the return value can be stored in the parameter `result`.

```Javascript
var result = window.Android.returnString();
```

If an attacker has access to the JavaScript code, through for example stored XSS or a MITM position he can directly call the exposed Java methods in order to exploit them.

##### Without Source Code

**..TODO..**

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]
**..TODO..**

#### Remediation

If `shouldOverrideUrlLoading()` is needed it should be verified how the input is processed and if it's possible to execute native functions through malicious JavaScript.

If `addJavascriptInterface()` is needed only JavaScript provided with the APK should be allowed to call it but no JavaScript loaded from remote endpoints.

Another compliant solution is to define the API level to 17 (JELLY_BEAN_MR1) and above in the manifest file of the App. For these API levels, only public methods that are annotated with JavascriptInterface can be accessed from JavaScript<sup>[1]</sup>.

```xml
<uses-sdk android:minSdkVersion="17" />
...

</manifest>
```

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link

##### OWASP MASVS

- V6.8: "If Java objects are exposed in a WebView, verify that the WebView only renders JavaScript contained within the app package."

##### CWE

- CWE-XXX - Title

##### Info

- [1] DRD13 addJavascriptInterface()  - https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=129859614
- [2] WebView addJavascriptInterface Remote Code Execution - https://labs.mwrinfosecurity.com/blog/webview-addjavascriptinterface-remote-code-execution/
- [3] Method shouldOverrideUrlLoading() - https://developer.android.com/reference/android/webkit/WebViewClient.html#shouldOverrideUrlLoading(android.webkit.WebView,%20java.lang.String)
- [4] Method addJavascriptInterface() - https://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object, java.lang.String)

##### Tools

* Tool - Link




### OMTG-ENV-009: Test for object serialization

#### Overview

Check <sup>[1]</sup>


#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link

##### OWASP MASVS

- V6.9: "Object serialization, if any, is implemented using safe serialization APIs."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Update Security Provider - https://developer.android.com/training/articles/security-gms-provider.html


##### Tools

* Tool - Link



### OMTG-ENV-010: Test for Root detection

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link

##### OWASP MASVS

- V6.10: "The app detects whether it is being executed on a rooted or jailbroken device. Depending on the business requirement, users are warned, or the app is terminated if the device is rooted or jailbroken."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link
