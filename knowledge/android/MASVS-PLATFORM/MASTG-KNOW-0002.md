---
masvs_category: MASVS-PLATFORM
platform: android
title: WebViews
---

## URL Loading in WebViews

WebViews are Android's embedded components which allow your app to open web pages within your application. In addition to mobile apps related threats, WebViews may expose your app to common web threats (e.g. XSS, Open Redirect, etc.).

One of the most important things to do when testing WebViews is to make sure that only trusted content can be loaded in it. Any newly loaded page could be potentially malicious, try to exploit any WebView bindings or try to phish the user. Unless you're developing a browser app, usually you'd like to restrict the pages being loaded to the domain of your app. A good practice is to prevent the user from even having the chance to input any URLs inside WebViews (which is the default on Android) nor navigate outside the trusted domains. Even when navigating on trusted domains there's still the risk that the user might encounter and click on other links to untrustworthy content (e.g. if the page allows for other users to post comments). In addition, some developers might even override some default behavior which can be potentially dangerous for the user.

## SafeBrowsing API

To provide a safer web browsing experience, Android 8.1 (API level 27) introduces the [`SafeBrowsing API`](https://developers.google.com/safe-browsing/v4), which allows your application to detect URLs that Google has classified as a known threat.

By default, WebViews show a warning to users about the security risk with the option to load the URL or stop the page from loading. With the SafeBrowsing API you can customize your application's behavior by either reporting the threat to SafeBrowsing or performing a particular action such as returning back to safety each time it encounters a known threat. Please check the [Android Developers documentation](https://developer.android.com/about/versions/oreo/android-8.1#safebrowsing) for usage examples.

You can use the SafeBrowsing API independently from WebViews using the [SafetyNet library](https://developer.android.com/training/safetynet/safebrowsing), which implements a client for Safe Browsing Network Protocol v4. SafetyNet allows you to analyze all the URLs that your app is supposed load. You can check URLs with different schemes (e.g. http, file) since SafeBrowsing is agnostic to URL schemes, and against `TYPE_POTENTIALLY_HARMFUL_APPLICATION` and `TYPE_SOCIAL_ENGINEERING` threat types.

> When sending URLs or files to be checked for known threats make sure they don't contain sensitive data which could compromise a user's privacy, or expose sensitive content from your application.

## Virus Total API

Virus Total provides an API for analyzing URLs and local files for known threats. The API Reference is available on [Virus Total developers page](https://developers.virustotal.com/reference#getting-started "Getting Started").

## JavaScript Execution in WebViews

JavaScript can be injected into web applications via reflected, stored, or DOM-based Cross-Site Scripting (XSS). Mobile apps are executed in a sandboxed environment and don't have this vulnerability when implemented natively. Nevertheless, WebViews may be part of a native app to allow web page viewing. Every app has its own WebView cache, which isn't shared with the native Browser or other apps.

On Android versions prior to 4.4, WebViews used the WebKit rendering engine to display web pages. Since Android 4.4, [WebViews have been based on Chromium](https://developer.android.com/about/versions/lollipop#WebView), providing improved performance and compatibility. However, the pages are still stripped down to minimal functions; for example, pages don't have address bars.

Android WebViews can use [`setJavaScriptEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled(boolean)) to enable JavaScript execution. This feature is disabled by default, but if enabled, it can be used to execute JavaScript code in the context of the loaded page. This can be dangerous if the WebView is loading untrusted content, as it can lead to XSS attacks. If you need to enable JavaScript, make sure that the content is trusted and that you have implemented proper input validation and output encoding. Otherwise, you can explicitly disable JavaScript:

```kotlin
webView.settings.apply {
    javaScriptEnabled = false
}
```

## WebView Local File Access Settings

These APIs control how a WebView accesses files on the local device. They determine whether the WebView can load files (such as HTML, images, or scripts) from the file system and whether JavaScript running in a local context can access additional local files. Note that accessing assets and resources (via file:///android_asset or file:///android_res) is always allowed regardless of these settings.

| API | Purpose | Defaults to `True` (API Level)   | Defaults to `False` (API Level) | Deprecated |
|-----|---------|-------------------------------------|-------------------------------------|------------|
| `setAllowFileAccess`  | Permits the WebView to load files from the local file system (using `file://` URLs)    | <= 29 (Android 10) | >= 30 (Android 11)          | No                                   |
| `setAllowFileAccessFromFileURLs`  | Allows JavaScript in a `file://` context to access other local `file://` URLs | <= 15 (Android 4.0.3) | >= 16 (Android 4.1)          | Yes (since API level 30, Android 11)       |
| `setAllowUniversalAccessFromFileURLs`    | Permits JavaScript in a `file://` context to access resources from any origin, bypassing the same-origin policy | <= 15 (Android 4.0.3) | >= 16 (Android 4.1) | Yes (since API level 30, Android 11)       |

**What files can be accessed by the WebView?:**

The WebView can access any file that the app has permission to access via `file://` URLs, including:

- Internal storage: the app's own internal storage.
- External storage
    - Before Android 10:
        - the entire external storage (SD card), if the app has the `READ_EXTERNAL_STORAGE` permission.
    - Since Android 10:
        - only the app-specific directories (due to scoped storage restrictions) without any special permissions.
        - entire media folders (including data from other apps) if the app has the `READ_MEDIA_IMAGES` or similar permissions.
        - the entire external storage if the app has the `MANAGE_EXTERNAL_STORAGE` permission.

## `setAllowFileAccess`

[`setAllowFileAccess`](https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess%28boolean%29 "Method setAllowFileAccess()") enables the WebView to load local files using the `file://` scheme. In this example, the WebView is configured to allow file access and then loads an HTML file from the external storage (sdcard).

```java
webView.settings.apply {
    allowFileAccess = true
}
webView.loadUrl("file:///sdcard/index.html");
```

## `setAllowFileAccessFromFileURLs`

[`setAllowFileAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccessFromFileURLs%28boolean%29 "Method setAllowFileAccessFromFileURLs()") allows the local file (loaded via file://) to access additional local resources from its HTML or JavaScript.

Note that the value of [**this setting is ignored**](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean)) if the value of `allowUniversalAccessFromFileURLs` is `true`.

> [Chromium WebView Docs](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md#setallowfileaccessfromfileurls): With this relaxed origin rule, URLs starting with `content://` and `file://` can access resources that have the same relaxed origin over `XMLHttpRequest`. For instance, `file://foo` can make an `XMLHttpRequest` to `file://bar`. Developers need to be careful so that a user provided data do not run in `content://` as it will allow the user's code to access arbitrary `content://` URLs those are provided by other applications. It will cause a serious security issue.
>
> Regardless of this API call, the [Fetch API](https://fetch.spec.whatwg.org/#fetch-api) does not allow accessing `content://` and `file://` URLs.

**Example:** In this example, the WebView is configured to allow file access and then loads an HTML file from the external storage (sdcard).

```java
webView.settings.apply {
    allowFileAccess = true
    allowFileAccessFromFileURLs = true
}
webView.loadUrl("file:///sdcard/local_page.html");
```

The loaded HTML file contains an image that is loaded via a `file://` URL:

```html
<!-- In local_page.html -->
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Local Page</title>
  </head>
  <body>
    <!-- This image is loaded via a file:// URL -->
    <img src="file:///android_asset/images/logo.png" alt="Logo">
  </body>
</html>
```

## `setAllowUniversalAccessFromFileURLs`

[`setAllowUniversalAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowUniversalAccessFromFileURLs%28boolean%29 "Method setAllowUniversalAccessFromFileURLs()") allows JavaScript running in a local file (loaded via `file://`) to bypass the same-origin policy and access resources from any origin.

> [Chromium WebView Docs](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/cors-and-webview-api.md#setallowuniversalaccessfromfileurls): When this API is called with true, URLs starting with `file://` will have a scheme based origin, and can access other scheme based URLs over `XMLHttpRequest`. For instance, `file://foo` can make an `XMLHttpRequest` to `content://bar`, `http://example.com/`, and `https://www.google.com/`. So developers need to manage data running under the `file://` scheme as it allows powerful permissions beyond the public web's CORS policy.
>
> Regardless of this API call, [Fetch API](https://fetch.spec.whatwg.org/#fetch-api) does not allow to access `content://` and `file://` URLs.

**Example:** In this example, the local HTML file successfully makes a cross-origin request to fetch data from an HTTPS endpoint. This can be potentially abused by an attacker to exfiltrate sensitive data from the app.

```kotlin
webView.settings.apply {
    javaScriptEnabled = true
    allowFileAccess = true
    allowUniversalAccessFromFileURLs = true
}
webView.loadUrl("file:///android_asset/local_page.html");
```

Contents of local_page.html (in the assets folder):

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Universal Access Demo</title>
    <script>
      // This AJAX call fetches data from a remote server despite being loaded via file://
      fetch("https://api.example.com/data")
        .then(response => response.text())
        .then(data => document.getElementById("output").innerText = data)
        .catch(err => console.error(err));
    </script>
  </head>
  <body>
    <div id="output">Loading...</div>
  </body>
</html>
```

**Note about accessing cookies:**

Setting `setAllowUniversalAccessFromFileURLs(true)` allows JavaScript inside a local `file://` to make cross-origin requests (XHR, Fetch, etc.). This bypasses the Same-Origin Policy (SOP) for network requests, but it does not grant access to cookies from remote websites.

- Cookies are managed by the WebView's CookieManager and cannot be accessed by a `file://` origin unless explicitly allowed via document.cookie (which most modern sites prevent using `HttpOnly` and `Secure` flags).
- Cross-origin requests also do not include cookies unless explicitly allowed by the server via CORS headers such as `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`.

## WebView Content Provider Access

WebViews can access [content providers](https://developer.android.com/guide/topics/providers/content-providers), which are used to share data between applications. Content providers can be accessed by other apps only if they are exported (`android:exported` attribute set to `true`), but even if the content provider is not exported, it can be accessed by a WebView in the application itself.

The setting `setAllowContentAccess` controls whether the WebView can access content providers using `content://` URLs. This setting is enabled by default for Android 4.1 (API level 16) and above.

> [Chromium WebView Docs](https://chromium.googlesource.com/chromium/src/%2B/HEAD/android_webview/docs/cors-and-webview-api.md#content_urls):
> `content://` URLs are used to access resources provided via Android Content Providers. The access should be permitted via `setAllowContentAccess` API beforehand. `content://` pages can contain iframes that load `content://` pages, but the parent frame can not access into the iframe contents. Also only `content://` pages can specify `content://` URLs for sub-resources.
>
> However, even pages loaded from `content://` can not make any [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)-enabled requests such as `XMLHttpRequest` to other `content://` URLs as each one is assumed to belong to an [opaque origin](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-opaque). See also `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs` sections as they can relax this default rule.
>
> Pages loaded with any scheme other than `content://` can't load `content://` page in iframes and they can not specify `content://` URLs for sub-resources.

**Example:** In this example, the WebView's `allowContentAccess` property is enabled and a `content://` URL is loaded.

```kotlin
webView.settings.apply {
    allowContentAccess = true
}
webView.loadUrl("content://com.example.myapp.provider/data");
```

**Which files can be accessed by the WebView?:**

The WebView can access any data accessible via content providers (if the app has any) using `content://` URLs. **Unless otherwise further restricted by the content provider**, this could include:

- Internal storage: the entire internal storage.
- External storage
    - Before Android 10:
        - the entire external storage (SD card), if the app has the `READ_EXTERNAL_STORAGE` permission.
    - Since Android 10:
        - only the app-specific directories (due to scoped storage restrictions) without any special permissions.
        - entire media folders (including data from other apps) if the app has the `READ_MEDIA_IMAGES` or similar permissions.
        - the entire external storage if the app has the `MANAGE_EXTERNAL_STORAGE` permission.

Data from other apps accessible via content providers (if the app has any and they are exported) can also be accessed.

## Java Objects Exposed Through WebViews

Android offers a way for JavaScript execution in a WebView to call and use native functions of an Android app (annotated with `@JavascriptInterface`) by using the [`addJavascriptInterface`](https://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface%28java.lang.Object,%20java.lang.String%29 "Method addJavascriptInterface()") method. This is known as a _WebView JavaScript bridge_ or _native bridge_.

Please note that **when you use `addJavascriptInterface`, you're explicitly granting access to the registered JavaScript Interface object to all pages loaded within that WebView**. This implies that, if the user navigates outside your app or domain, all other external pages will also have access to those JavaScript Interface objects which might present a potential security risk if any sensitive data is being exposed though those interfaces.

> Warning: Take extreme care with apps targeting Android versions below Android 4.2 (API level 17) as they are [vulnerable to a flaw](https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution "WebView addJavascriptInterface Remote Code Execution") in the implementation of `addJavascriptInterface`: an attack that is abusing reflection, which leads to remote code execution when malicious JavaScript is injected into a WebView. This was due to all Java Object methods being accessible by default (instead of only those annotated).

## WebViews Cleanup

Clearing the WebView resources is a crucial step when an app accesses any sensitive data within a WebView. This includes any files stored locally, the RAM cache and any loaded JavaScript.

As an additional measure, you could use server-side headers such as `no-cache`, which prevent an application from caching particular content.

> Starting on Android 10 (API level 29) apps are able to detect if a WebView has become [unresponsive](https://developer.android.com/about/versions/10/features?hl=en#webview-hung "WebView hung renderer detection"). If this happens, the OS will automatically call the `onRenderProcessUnresponsive` method.

You can find more security best practices when using WebViews on [Android Developers](https://developer.android.com/training/articles/security-tips?hl=en#WebView "Security Tips - Use WebView").
