---
title: Securely Load File Content in a WebView
alias: securely-load-file-content-in-webview
id: MASTG-BEST-0011
platform: android
---

The recommended approach to **load file content to a WebView securely** is to use [`WebViewClient`](https://developer.android.com/reference/android/webkit/WebViewClient) with [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader) to load assets from the app's assets or resources directory using `https://` URLs instead of insecure `file://` URLs. This ensures the content is loaded in a secure, same-origin environment and avoids exposing local files to potential cross-origin attacks.

If you must allow the WebView to load local files using the `file://` scheme, consider the following:

- For apps with a `minSdkVersion` that has secure defaults for WebView file access methods, ensure that these methods are **not used** and the default values are preserved. Alternatively, explicitly set them to `false` to guarantee the WebView does not allow local file access:
    - `setAllowFileAccess(false)`
    - `setAllowFileAccessFromFileURLs(false)`
    - `setAllowUniversalAccessFromFileURLs(false)`

- For apps with a `minSdkVersion` that **does not have secure defaults** for these methods (e.g., older API levels), ensure that the above methods are **explicitly** set to `false` in your WebView configuration.

For more details, refer to the [official Android documentation on loading local content securely](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content), especially the section on ["Things to avoid"](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content#antipatterns).
