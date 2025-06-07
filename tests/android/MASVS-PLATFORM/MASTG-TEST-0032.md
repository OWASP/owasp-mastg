---
masvs_v1_id:
- MSTG-PLATFORM-6
masvs_v2_id:
- MASVS-PLATFORM-2
platform: android
title: Testing WebView Protocol Handlers
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0250, MASTG-TEST-0251, MASTG-TEST-0252, MASTG-TEST-0253]
deprecation_note: New version available in MASTG V2
---

## Overview

To test for [WebView protocol handlers (or resource access)](../../../Document/0x05h-Testing-Platform-Interaction.md#webview-local-file-access-settings) check the app for WebView usage and evaluate whether or not the WebView should have resource access. If resource access is necessary you need to verify that it's implemented following best practices.

## Static Analysis

Check the source code for WebView usage. The following [WebView settings](https://developer.android.com/reference/android/webkit/WebSettings.html "WebView Settings") control resource access:

- `setAllowContentAccess`: Content URL access allows WebViews to load content from a content provider installed on the system, which is enabled by default .
- `setAllowFileAccess`: Enables and disables file access within a WebView. The default value is `true` when targeting Android 10 (API level 29) and below and `false` for Android 11 (API level 30) and above. Note that this enables and disables [file system access](https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess%28boolean%29 "File Access in WebView") only. Asset and resource access is unaffected and accessible via `file:///android_asset` and `file:///android_res`.
- `setAllowFileAccessFromFileURLs`: Does or does not allow JavaScript running in the context of a file scheme URL to access content from other file scheme URLs. The default value is `true` for Android 4.0.3 - 4.0.4 (API level 15) and below and `false` for Android 4.1 (API level 16) and above.
- `setAllowUniversalAccessFromFileURLs`: Does or does not allow JavaScript running in the context of a file scheme URL to access content from any origin. The default value is `true` for Android 4.0.3 - 4.0.4 (API level 15) and below and `false` for Android 4.1 (API level 16) and above.

If one or more of the above methods is/are activated, you should determine whether the method(s) is/are really necessary for the app to work properly.

If a WebView instance can be identified, find out whether local files are loaded with the [`loadURL`](https://developer.android.com/reference/android/webkit/WebView.html#loadUrl%28java.lang.String%29 "loadURL in WebView") method.

```java
WebView = new WebView(this);
webView.loadUrl("file:///android_asset/filename.html");
```

The location from which the HTML file is loaded must be verified. If the file is loaded from external storage, for example, the file is readable and writable by everyone. This is considered a bad practice. Instead, the file should be placed in the app's assets directory.

```java
webview.loadUrl("file:///" +
Environment.getExternalStorageDirectory().getPath() +
"filename.html");
```

The URL specified in `loadURL` should be checked for dynamic parameters that can be manipulated; their manipulation may lead to local file inclusion.

Use the following [code snippet and best practices](https://github.com/nowsecure/secure-mobile-development/blob/master/en/android/webview-best-practices.md#remediation "WebView best practices") to deactivate protocol handlers, if applicable:

```java
//If attackers can inject script into a WebView, they could access local resources. This can be prevented by disabling local file system access, which is enabled by default. You can use the Android WebSettings class to disable local file system access via the public method `setAllowFileAccess`.
webView.getSettings().setAllowFileAccess(false);

webView.getSettings().setAllowFileAccessFromFileURLs(false);

webView.getSettings().setAllowUniversalAccessFromFileURLs(false);

webView.getSettings().setAllowContentAccess(false);
```

- Create a list that defines local and remote web pages and protocols that are allowed to be loaded.
- Create checksums of the local HTML/JavaScript files and check them while the app is starting up. Minify JavaScript files to make them harder to read.

## Dynamic Analysis

To identify the usage of protocol handlers, look for ways to trigger phone calls and ways to access files from the file system while you're using the app.
