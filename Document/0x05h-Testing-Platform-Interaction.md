## Testing Platform Interaction

### Testing App Permissions

#### Overview

Android assigns every installed app with a distinct system identity (Linux user ID and group ID). Because each Android app operates in a process sandbox, apps must explicitly request access to resources and data outside their sandbox. They request this access by declaring the permissions they need to use certain system data and features. Depending on how sensitive or critical the data or feature is, Android system will grant the permission automatically or ask the user to approve the request.

Android permissions are classified in four different categories based on the protection level it offers.

- **Normal**: This permission gives apps access to isolated application-level features, with minimal risk to other apps, the user or the system. It is granted during the installation of the App. If no protection level is specified, normal is the default value. Example: `android.permission.INTERNET`
- **Dangerous**: This permission usually gives the app control over user data or control over the device that impacts the user. This type of permission may not be granted at installation time, leaving it to the user to decide whether the app should have the permission or not. Example: `android.permission.RECORD_AUDIO`
- **Signature**: This permission is granted only if the requesting app was signed with the same certificate as the app that declared the permission. If the signature matches, the permission is automatically granted. Example: `android.permission.ACCESS_MOCK_LOCATION`
- **SystemOrSignature**: Permission only granted to applications embedded in the system image or that were signed using the same certificated as the application that declared the permission. Example: `android.permission.ACCESS_DOWNLOAD_MANAGER`

Full list of Android Permissions [here](https://developer.android.com/reference/android/Manifest.permission.html#ACCESS_LOCATION_EXTRA_COMMANDS).

Android allow apps to expose their services/components to other apps and custom permissions are required to restrict which app can access the exposed component. Custom permission can be easily defined in `AndroidManifest.xml` file, by creating a permission tag with two mandatory attributes: `android:name` and `android:protectionLevel`. It is crucial to create custom permission that adhere to the _Principle of Least Privilege_: permission should be define explicitly for its purpose with meaningful and accurate label and description.


Below is an example of a custom permission `START_MAIN_ACTIVITY` that required when launching the `TEST_ACTIVITY` Activity.

The first code block defines the new permission which is self-explanatory. The label tag is a summary of the permission and description is a more detailed description of the summary. The protection level can be set based on the types of permission it is granting.
Once you have defined your permission, it can be enforced on the component by specifying it in the application’s manifest. In our example, the second block is the component that we are going to restrict with the permission we created. It can be easily enforced by adding the `android:permission` attributes.

```xml
<permission android:name=“com.example.myapp.permission.START_MAIN_ACTIVITY”
        android:label=“Start Activity in myapp"
        android:description=“Allow the app to launch the activity of myapp app, any app you grant this permission will be able to launch main activity by myapp app."
        android:protectionLevel=“normal" />

<activity android:name=“TEST_ACTIVITY”
    android:permission=“com.example.myapp.permission.START_MAIN_ACTIVITY”>
    <intent-filter>
        <action android:name=“android.intent.action.MAIN" />
        <category android:name=“android.intent.category.LAUNCHER”/>
     </intent-filter>
</activity>
```

Now that the new permission `START_MAIN_ACTIVTY` is created, apps can request it using the `uses-permision` tag in the `AndroidManifest.xml` file. Any application can now launch the `TEST_ACTIVITY` if it is granted with the custom permission `START_MAIN_ACTIVITY`.

```xml
<uses-permission android:name=“com.example.myapp.permission.START_MAIN_ACTIVITY”/>
```

#### Static Analysis

##### With Source Code

###### Android Permissions

Permissions should be checked if they are really need within the App. For example in order for an Activity to load a web page into a WebView the `INTERNET` permission in the Android Manifest file is needed.

```xml
<uses-permission android:name="android.permission.INTERNET" />
```
It is always recommended to run through the developer of the intention of every permission and removed those that are not needed.

###### Custom Permissions

Apart from enforcing custom permissions via application manifest file, it can also be enforce programmatically. This is not recommended as this can lead to permission leaking and perform an unauthorized operation. This can be verified by inspecting whether if all defined custom permission were enforce in android manifest file.

```java
int canProcess = checkCallingOrSelfPermission(
“com.example.perm.READ_INCOMING_MSG”);
if (canProcess != PERMISSION_GRANTED)
throw new SecurityException();

```

##### Without Source Code

To review application permissions via Android Manifest file, the APK file will need to be unpacked with apktool. It will then generate a folder that contains the Android Manifest file.

```bash
$apktool d test.apk

I: Using Apktool 2.2.1 on test.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /Users/tnayr/Library/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Baksmaling classes2.dex...
I: Copying assets and libs...
I: Copying unknown files…
I: Copying original files...
```

Within the manifest file, requested permissions will be declared as `uses-permissions` tag.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.owasp.mstg.myapp" >
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    ...
</manifest>
```

Alternatively, Android Asset Packaging tool can be used to examine permissions.

```bash
$ aapt d permissions com.owasp.mstg.myapp
uses-permission: android.permission.WRITE_CONTACTS
uses-permission: android.permission.CHANGE_CONFIGURATION
uses-permission: android.permission.SYSTEM_ALERT_WINDOW
uses-permission: android.permission.INTERNAL_SYSTEM_WINDOW
```

#### Dynamic Analysis

Dynamic analysis is not applicable and a solid statement and result for this test case can only be done after reviewing the Android Manifest. See "Static Analysis" for details.

#### Remediation

Only permissions that are used within the app should be requested in the Android Manifest. All other permissions should be removed.

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 concerning this section] --

##### OWASP MASVS

- V6.1: "The app only requires the minimum set of permissions necessary."

##### CWE

-- TODO [Add reference to relevant CVE(s) : titles, links, ...] --

##### Info

- [1] Android Permissions - https://developer.android.com/guide/topics/permissions/requesting.html
- [2] Custom Permissions - https://developer.android.com/guide/topics/permissions/defining.html
- [3] An In-Depth Introduction to the Android Permission Model - https://www.owasp.org/images/c/ca/ASDC12-An_InDepth_Introduction_to_the_Android_Permissions_Modeland_How_to_Secure_MultiComponent_Applications.pdf


##### Tools

-- TODO [Add link to relevant tools] --

### Testing Input Validation and Sanitization

#### Overview

-- TODO [Provide a general description of the issue.] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Clarify the purpose of "[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]" ] --

##### With Source Code

-- TODO [Develop content for "Testing Input Validation and Sanitization" with source code] --

##### Without Source Code

-- TODO [Develop content for "Testing Input Validation and Sanitization" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue.] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add link to MX OWASP Mobile Top 10 2014] --
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update below "X.Y" reference to MASVS] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add links and titles to relevant CWE] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add links to relevant tools] --
* Enjarify - https://github.com/google/enjarify


### Testing Custom URL Schemes

#### Overview

Both Android and iOS allow inter-app communication through the use of custom URL schemes. These custom URLs allow other applications to perform specific actions within the application hosting the custom URL scheme. Much like a standard web URL that might start with `https://`, custom URIs can begin with any scheme prefix and usually define an action to take within the application and parameters for that action.

As a contrived example, consider: `sms://compose/to=your.boss@company.com&messsage=I%20QUIT!&sendImmediately=true`. Using something like this embedded as a link on a web page, when clicked by a victim on their mobile device, calling the custom URI with maliciously crafted parameters might trigger an SMS to be sent by the vulnerable SMS application with attacker defined content.

For any application, each of these custom URL schemes needs to be enumerated, and the actions they perform need to be tested.

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Clarify the purpose of "[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]" ] --

##### With Source Code

-- TODO [Develop content for "Testing Custom URL Schemes" with source code] --

##### Without Source Code

-- TODO [Develop content for "Testing Custom URL Schemes" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue.] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for the "Testing Custom URL Schemes" topic] --

##### OWASP MASVS

- V6.3: "The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected."

##### CWE

-- TODO [Add link to relevant CWE for "Testing Custom URL Schemes"]

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

-- TODO [Add link to tools for "Testing Custom URL Schemes"] --


### Testing For Sensitive Functionality Exposure Through IPC

#### Overview

-- TODO [Provide a general description of the issue.] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Clarify purpose of "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content for "Testing For Sensitive Functionality Exposure Through IPC" with source code] --

##### Without Source Code

-- TODO [Add content for "Testing For Sensitive Functionality Exposure Through IPC" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue.] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for the "Testing For Sensitive Functionality Exposure Through IPC" topic] --

##### OWASP MASVS

- V6.4: "The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected."

##### CWE

-- TODO [Add links and titles for CWE related to the "Testing For Sensitive Functionality Exposure Through IPC" topic] --

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### Tools

-- TODO [Add links to relevant tools for the "Testing For Sensitive Functionality Exposure Through IPC" topic] --

### Testing JavaScript Execution in WebViews

#### Overview

In Web applications, JavaScript can be injected in many ways by leveraging reflected, stored or DOM based Cross-Site Scripting (XSS). Mobile Apps are executed in a sandboxed environment and when implemented natively do not possess this attack vector. Nevertheless, WebViews can be part of a native App to allow viewing of web pages. Every App has it's own cache for WebViews and doesn't share it with the native Browser or other Apps. WebViews in Android are using the WebKit rendering engine to display web pages but are stripped down to a minimum of functions, as for example no address bar is available. If the WebView is implemented too lax and allows the usage of JavaScript it can be used to to attack the App and gain access to it's data.

#### Static Analysis

##### With Source Code

To create and use a WebView, an instance of the class WebView need to be created.

```Java
WebView webview = new WebView(this);
setContentView(webview);
webview.loadUrl("http://slashdot.org/");
```

Different settings can be applied to the WebView of which one is able to activate and deactivate JavaScript. By default JavaScript is disabled in a WebView, so it need to be explicitly enabled. Look for the method `setJavaScriptEnabled` to check if JavaScript is activated.

```Java
webview.getSettings().setJavaScriptEnabled(true);
```

This allows the WebView to interpret JavaScript and execute it's command.


##### Without Source Code

-- TODO [Add content on "Testing JavaScript Execution in WebViews" without source code] --

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

The cache of the WebView should also be cleared in order to remove all JavaScript and locally stored data, by using `clearCache()`<sup>[2]</sup> when closing the App.

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

-- TODO [Add link to tools for "Testing JavaScript Execution in WebViews"] --


### Testing WebView Protocol Handlers

#### Overview

Several schemas are available by default in an URI on Android and can be triggered within a WebView<sup>[3]</sup>, e.g:

* http(s):
* file:
* tel:
* geo:

When using them in a link the App can be triggered for example to access a local file when using `file:///storage/emulated/0/private.xml`. This can be exploited by an attacker if he is able to inject JavaScript into the Webview to access local resources via the file schema.

-- TODO [Further develop content on "Testing WebView Protocol Handlers"] --

#### Static Analysis

##### With Source Code

The following methods are available for WebViews to control access to different resources<sup>[4]</sup>:

* `setAllowContentAccess()`: Content URL access allows WebView to load content from a content provider installed in the system. The default is enabled.
* `setAllowFileAccess()`: Enables or disables file access within WebView. File access is enabled by default.
* `setAllowFileAccessFromFileURLs()`: Sets whether JavaScript running in the context of a file scheme URL should be allowed to access content from other file scheme URLs. The default value is true for API level _ICE_CREAM_SANDWICH_MR1_ and below, and false for API level _JELLY_BEAN_ and above.
* `setAllowUniversalAccessFromFileURLs()`: Sets whether JavaScript running in the context of a file scheme URL should be allowed to access content from any origin. The default value is true for API level ICE_CREAM_SANDWICH_MR1 and below, and false for API level JELLY_BEAN and above.

If one or all of the methods above can be identified and they are activated it should be verified if it is really needed for the App to work properly.

##### Without Source Code

-- TODO [Create content on "Testing WebView Protocol Handlers" with source code] --

#### Dynamic Analysis

While using the App look for ways to trigger phone calls or accessing files from the file system to identify usage of protocol handlers.

-- TODO [Further develop content on dynamic analysis for "Testing WebView Protocol Handlers" ] --

#### Remediation

Set the following best practices in order to deactivate protocol handlers, if applicable<sup>[2]</sup>:

```java
//Should an attacker somehow find themselves in a position to inject script into a WebView, then they could exploit the opportunity to access local resources. This can be somewhat prevented by disabling local file system access. It is enabled by default. The Android WebSettings class can be used to disable local file system access via the public method setAllowFileAccess.
webView.getSettings().setAllowFileAccess(false);

webView.getSettings().setAllowFileAccessFromFileURLs(false);

webView.getSettings().setAllowUniversalAccessFromFileURLs(false);

webView.getSettings().setAllowContentAccess(false);
```

Access to files in the file system can be enabled and disabled for a WebView with `setAllowFileAccess()`. File access is enabled by default and should be deactivated if not needed. Note that this enables or disables file system access only. Assets and resources are still accessible using `file:///android_asset` and `file:///android_res`<sup>[1]</sup>.

-- TODO [How to disable tel and geo schema?] --

#### References

##### OWASP Mobile Top 10 2014

* M7 - Client Side Injection

##### OWASP MASVS

- V6.6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."

##### CWE

-- TODO [Add links and titles to relevant CWE for "Testing WebView Protocol Handlers"] --

##### Info

- [1] File Access in WebView - https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess%28boolean%29
- [2] WebView best practices - https://github.com/nowsecure/secure-mobile-development/blob/master/en/android/webview-best-practices.md#remediation
- [3] Intent List - https://developer.android.com/guide/appendix/g-app-intents.html
- [4] WebView Settings - https://developer.android.com/reference/android/webkit/WebSettings.html


##### Tools

-- TODO [Add links to relevant tools for "Testing WebView Protocol Handlers"] --

### Testing for Local File Inclusion in WebViews

#### Overview

WebViews can load content remotely, but can also load it locally from the App data directory or external storage. If the content is loaded locally it should not be possible by the user to influence the filename or path where the file is loaded from or should be able to edit the loaded file.

-- TODO [Further develop content on the overview for "Testing for Local File Inclusion in WebViews"] --

#### Static Analysis

##### With Source Code

Check the source code for the usage of WebViews. If a WebView instance can be identified check if local files are loaded through the method `loadURL()`<sup>[1]</sup>.

```Java
WebView webview = new WebView(this);
webView.loadUrl("file:///android_asset/filename.html");
```

It needs to be verified where the HTML file is loaded from. For example if it's loaded from the external storage the file is read and writable by everybody and considered a bad practice.

```java
webview.loadUrl("file:///" +
Environment.getExternalStorageDirectory().getPath() +
"filename.html");
```

The URL specified in `loadURL()` should be checked, if any dynamic parameters are used that can be manipulated, which may lead to local file inclusion.


##### Without Source Code

-- TODO [Develop content for "Testing for Local File Inclusion in WebViews" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

Create a white-list that defines the web pages and it's protocols (HTTP or HTTPS) that are allowed to be loaded locally and remotely. Loading web pages from the external storage should be avoided as they are read and writable for all users in Android. Instead they should be placed in the assets directory of the App.

Create checksums of the local HTML/JavaScript files and check it during start up of the App. Minify JavaScript files in order to make it harder to read them.

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing for Local File Inclusion in WebViews"] --

##### OWASP MASVS

- V6.7: "The app does not load user-supplied local resources into WebViews."

##### CWE

-- TODO [Add reference to relevant CWE for "Testing for Local File Inclusion in WebViews"] --

##### Info

- [1] loadURL() in WebView - https://developer.android.com/reference/android/webkit/WebView.html#loadUrl(java.lang.String)


##### Tools

-- TODO [Add links to tools for "Testing for Local File Inclusion in WebViews"] --


### Testing Whether Java Objects Are Exposed Through WebViews

#### Overview

Android offers two different ways that enables JavaScript executed in a WebView to call and use native functions within an Android App:

* `shouldOverrideUrlLoading()`<sup>[4]</sup>
* `addJavascriptInterface()`<sup>[5]</sup>

**shouldOverrideUrlLoading**

This method gives the host application a chance to take over the control when a new URL is about to be loaded in the current WebView.  The method `shouldOverrideUrlLoading()` is available with two different method signatures:

* `boolean shouldOverrideUrlLoading` (WebView view, String url)
  * This method was deprecated in API level 24.
* `boolean shouldOverrideUrlLoading` (WebView view, WebResourceRequest request)
  * This method was added in API level 24

**addJavascriptInterface**

The `addJavascriptInterface()` method allows to expose Java Objects to WebViews. When using this method in an Android App it is possible for JavaScript code in a WebView to invoke native methods of the Android App.

Before Android 4.2 JELLY_BEAN (API Level 17) a vulnerability was discovered in the implementation of `addJavascriptInterface()`, by using reflection that leads to remote code execution when injecting malicious JavaScript in a WebView<sup>[2]</sup>.

With API Level 17 this vulnerability was fixed and the access granted to methods of a Java Object for JavaScript was changed. When using `addJavascriptInterface()`, methods of a Java Object are only accessible for JavaScript when the annotation `@JavascriptInterface` is explicitly added. Before API Level 17 all methods of the Java Object were accessible by default.

An App that is targeting an Android version before Android 4.2 is still vulnerable to the identified flaw in `addJavascriptInterface()` and should only be used with extreme care. Therefore several best practices should be applied in case this method is needed.


#### Static Analysis

##### With Source Code

**shouldOverrideUrlLoading**

It needs to be verified if and how the method `shouldOverrideUrlLoading()` is used and if it's possible for an attacker to inject malicious JavaScript.

The following example illustrates how the method can be used.

```Java
@Override
public boolean shouldOverrideUrlLoading (WebView view, WebResourceRequest request) {
    URL url = new URL(request.getUrl().toString());
    // execute functions according to values in URL
  }
}
```

If an attacker has access to the JavaScript code, for example through stored XSS or MITM, he can directly trigger native functions if the exposed Java methods are implemented in an insecure way.

```javascript
window.location = http://example.com/method?parameter=value
```


**addJavascriptInterface**

It need to be verified if and how the method `addJavascriptInterface()` is used and if it's possible for an attacker to inject malicious JavaScript.

The following example shows how `addJavascriptInterface` is used in a WebView to bridge a Java Object to JavaScript:

```Java
WebView webview = new WebView(this);
WebSettings webSettings = webview.getSettings();
webSettings.setJavaScriptEnabled(true);

MSTG_ENV_008_JS_Interface jsInterface = new MSTG_ENV_008_JS_Interface(this);

myWebView.addJavascriptInterface(jsInterface, "Android");
myWebView.loadURL("http://example.com/file.html");
setContentView(myWebView);
```

In Android API level 17 and above, a special annotation is used to explicitly allow the access from JavaScript to a Java method.


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

If the annotation `@JavascriptInterface` is used, this method can be called from JavaScript. If the App is targeting API level < 17, all methods of the Java Object are exposed to JavaScript and can be called.

In JavaScript the method `returnString()` can now be called and the return value can be stored in the parameter `result`.

```Javascript
var result = window.Android.returnString();
```

If an attacker has access to the JavaScript code, for example through stored XSS or MITM, he can directly call the exposed Java methods in order to exploit them.

##### Without Source Code

-- TODO [Add content on "Testing Whether Java Objects Are Exposed Through WebViews" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

If `shouldOverrideUrlLoading()` is needed, it should be verified how the input is processed and if it's possible to execute native functions through malicious JavaScript.

If `addJavascriptInterface()` is needed, only JavaScript provided with the APK should be allowed to call it but no JavaScript loaded from remote endpoints.

Another compliant solution is to define the API level to 17 (JELLY_BEAN_MR1) and above in the manifest file of the App. For these API levels, only public methods that are annotated with `JavascriptInterface` can be accessed from JavaScript<sup>[1]</sup>.

```xml
<uses-sdk android:minSdkVersion="17" />
...

</manifest>
```

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for the "Testing Whether Java Objects Are Exposed Through WebViews" issue] --

##### OWASP MASVS

- V6.8: "If Java objects are exposed in a WebView, verify that the WebView only renders JavaScript contained within the app package."

##### CWE

-- TODO [Add links and titles to relevant CWE for "Testing Whether Java Objects Are Exposed Through WebViews"] --

##### Info

- [1] DRD13 addJavascriptInterface()  - https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=129859614
- [2] WebView addJavascriptInterface Remote Code Execution - https://labs.mwrinfosecurity.com/blog/webview-addjavascriptinterface-remote-code-execution/
- [3] Method shouldOverrideUrlLoading() - https://developer.android.com/reference/android/webkit/WebViewClient.html#shouldOverrideUrlLoading(android.webkit.WebView,%20java.lang.String)
- [4] Method addJavascriptInterface() - https://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object, java.lang.String)

##### Tools

-- TODO [Add links to tools for "Testing Whether Java Objects Are Exposed Through WebViews"] --


### Testing Object (De-)Serialization

#### Overview

An object and it's data can be represented as a sequence of bytes. In Java, this is possible using object serialization. Serialization is not secure by default and is just a binary format or representation that can be used to store data locally as .ser file. It is possible to sign and encrypt serialized data but, if the source code is available, this is always reversible.  

#### Static Analysis

##### With Source Code

Search the source code for the following keywords:

* `import java.io.Serializable`
* `implements Serializable`

Check if serialized data is stored temporarily or permanently within the app's data directory or external storage and if it contains sensitive data.

**https://www.securecoding.cert.org/confluence/display/java/SER04-J.+Do+not+allow+serialization+and+deserialization+to+bypass+the+security+manager**


##### Without Source Code

-- TODO [Create content for "Testing Object (De-)Serialization" without source code] --

#### Dynamic Analysis

-- TODO [Create content for dynamic analysis of "Testing Object (De-)Serialization" ] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Object (De-)Serialization".] --

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing Object (De-)Serialization"] --

##### OWASP MASVS

- V6.9: "Object serialization, if any, is implemented using safe serialization APIs."

##### CWE

-- TODO [Add link and title to CWE for "Testing Object (De-)Serialization"] --

##### Info

- [1] Update Security Provider - https://developer.android.com/training/articles/security-gms-provider.html


##### Tools

-- TODO [Add link to relevant tools for "Testing Object (De-)Serialization"] --


### Testing Root Detection

#### Overview

Checking the integrity of the environment where the app is running is getting more and more common on the Android platform. Due to the usage of rooted devices several fundamental security mechanisms of Android are deactivated or can easily be bypassed by any app. Apps that process sensitive information or have built in largely intellectual property (IP), like gaming apps, might want to avoid to run on a rooted phone to protect data or their IP.

Keep in mind that root detection is not protecting an app from attackers, but can slow down an attacker dramatically and higher the bar for successful local attacks. Root detection should be considered as part of a broad security-in-depth strategy, to be more resilient against attackers and make analysis harder.

#### Static Analysis

##### With Source Code

Root detection can either be implemented by leveraging existing root detection libraries, such as `Rootbeer`<sup>[1]</sup>, or by implementing manually checks.

Check the source code for the string `rootbeer` and also the `gradle` file, if a dependency is defined for Rootbeer:

```java
dependencies {
    compile 'com.scottyab:rootbeer-lib:0.0.4'
}
```

If this library is used, code like the following might be used for root detection.

```java
        RootBeer rootBeer = new RootBeer(context);
        if(rootBeer.isRooted()){
            //we found indication of root
        }else{
            //we didn't find indication of root
        }
```

If the root detection is implemented from scratch, the following should be checked to identify functions that contain the root detection logic. The following checks are the most common ones for root detection:
* Checking for settings/files that are available on a rooted device, like verifying the BUILD properties for test-keys in the parameter `android.os.build.tags`.
* Checking permissions of certain directories that should be read-only on a non-rooted device, but are read/write on a rooted device.
* Checking for installed Apps that allow or support rooting of a device, like verifying the presence of _Superuser.apk_.
* Checking available commands, like is it possible to execute `su` and being root afterwards.


##### Without Source Code

-- TODO [Create content for "Testing Root Detection" without source code] --

#### Dynamic Analysis

A debug build with deactivated root detection should be provided in a white box test to be able to apply all test cases to the app.

In case of a black box test, an implemented root detection can be challenging if for example the app is immediately terminated because of a rooted phone. Ideally, a rooted phone is used for black box testing and might also be needed to disable SSL Pinning. To deactivate SSL Pinning and allow the usage of an interception proxy, the root detection needs to be defeated first in that case. Identifying the implemented root detection logic without source code in a dynamic scan can be fairly hard.

By using the Xposed module `RootCloak`<sup>[2]</sup> it is possible to run apps that detect root without disabling root. Nevertheless, if a root detection mechanism is used within the app that is not covered in RootCloak, this mechanism needs to be identified and added to RootCloak in order to disable it.

Other options are dynamically patching the app with Friday or repackaging the app. This can be as easy as deleting the function in the smali code and repackage it, but can become difficult if several different checks are part of the root detection mechanism. Dynamically patching the app can also become difficult if countermeasures are implemented that prevent runtime manipulation/tampering.

Otherwise it should be switched to a non-rooted device in order to use the testing time wisely and to execute all other test cases that can be applied on a non-rooted setup. This is of course only possible if the SSL Pinning can be deactivated for example in smali and repackaging the app.

#### Remediation

To implement root detection within an Android app, libraries can be used like `RootBeer`<sup>[1]</sup>. The root detection should either trigger a warning to the user after start, to remind him that the device is rooted and that the user can only proceed on his own risk. Alternatively, the app can terminate itself in case a rooted environment is detected. This decision is depending on the business requirements and the risk appetite of the stakeholders.

#### References

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2414 for "Testing Root Detection"] --

##### OWASP MASVS

- V6.10: "The app detects whether it is being executed on a rooted or jailbroken device. Depending on the business requirement, users are warned, or the app is terminated if the device is rooted or jailbroken."

##### CWE

-- TODO [Add link to relevant CWE for "Testing Root Detection"] --

##### Info
- [1] RootBeer - https://github.com/scottyab/rootbeer

##### Tools

* [2] RootCloak - http://repo.xposed.info/module/com.devadvance.rootcloak2
