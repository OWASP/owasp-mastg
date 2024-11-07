---
Title: Testing for URL Loading in WebViews
ID: MASTG-TEST-0027
Link: https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/
Platform: android
type: [static]
MASVS v1: ['MSTG-PLATFORM-2']
MASVS v2: ['MASVS-CODE-4']
---

## Overview

By default, navigation events inside of a WebView will redirect to the default browser application. However, it is possible to stay within the WebView and handle all new page loads. This can be dangerous, as the new page may be malicous and interact with either the JavaScript bridge, or phish the user. The application should monitor navigation events inside the WebView to make sure that only legitimate pages are loaded, while others are redirected to the browser application.

## Steps

1. 
To test if the app is overriding the default page navigation logic by configuring a `WebViewClient`, search for and inspect the following interception callback functions:

- `shouldOverrideUrlLoading` allows your application to either abort loading pages with suspicious content by returning `true` or allow the WebView to load the URL by returning `false`. Considerations:
    - This method is not called for POST requests.
    - This method is not called for XmlHttpRequests, iFrames, "src" attributes included in HTML or `<script>` tags. Instead, `shouldInterceptRequest` should take care of this.
- `shouldInterceptRequest` allows the application to return the data from resource requests. If the return value is null, the WebView will continue to load the resource as usual. Otherwise, the data returned by the `shouldInterceptRequest` method is used. Considerations:
    - This callback is invoked for a variety of URL schemes (e.g., `http(s):`, `data:`, `file:`, etc.), not only those schemes which send requests over the network.
    - This is not called for `javascript:` or `blob:` URLs, or for assets accessed via `file:///android_asset/` or `file:///android_res/` URLs.
  In the case of redirects, this is only called for the initial resource URL, not any subsequent redirect URLs.
    - When Safe Browsing is enabled, these URLs still undergo Safe Browsing checks but the developer can allow the URL with `setSafeBrowsingWhitelist` or even ignore the warning via the `onSafeBrowsingHit` callback. Safe Browsing can also fully be disabled by using `setSafeBrowsingEnabled(false)`.

As you can see there are a lot of points to consider when testing the security of WebViews that have a WebViewClient configured, so be sure to carefully read and understand all of them by checking the [`WebViewClient` Documentation](https://developer.android.com/reference/android/webkit/WebViewClient "WebViewClient").

## Observation

The output could contain references to `WebViewClient` or calls to `shouldInterceptRequest`, `shouldOverrideUrlLoading` and `setSafeBrowsingEnabled`.

## Evaluation

The test case fails if the `WebView` has a custom `WebViewClient` and one of the following is true:

- SafeSearch is disabled via `setSafeBrowsingEnabled(false)`
- The `WebViewClient` is missing the `shouldOverrideUrlLoading` or `shouldInterceptRequest` handlers
- The `shouldOverrideUrlLoading` or `shouldInterceptRequest` handlers do not correctly prevent untrusted data from being loaded in the `WebView`

If the `WebView` does not have a custom `WebViewClient`, then any navigation event will automatically trigger the default browswer.
