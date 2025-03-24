---
title: Securely Load File Content in a WebView
alias: securely-load-file-content-in-webview
id: MASTG-BEST-0011
platform: android
---

The recommended approach to **load file content in a WebView securely** is to use [`WebViewClient`](https://developer.android.com/reference/android/webkit/WebViewClient) with [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader) to load assets from the app's assets directory using `https://` instead of `file://` URLs.

If you must allow the WebView to load local files using the `file://` scheme, ensure that the following methods from the [`WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings) class are **not used** or are **explicitly set to `false`**:

- For apps with a `minSdkVersion` that has secure defaults for these methods, ensure that the methods are **not used** and the default values are assumed. Alternatively, explicitly set the methods to `false` to ensure that the WebView does not load local files in any case.
- For apps with a `minSdkVersion` that **does not have secure defaults** for these methods, ensure that the methods are used and **explicitly** set to `false`.
