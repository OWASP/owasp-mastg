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

In order to test for [URL loading in WebViews](../../../Document/0x05h-Testing-Platform-Interaction.md#url-loading-in-webviews "URL Loading in WebViews") you need to carefully analyze [handling page navigation](https://developer.android.com/guide/webapps/webview#HandlingNavigation "Handling page navigation"), especially when users might be able to navigate away from a trusted environment. The default and safest behavior on Android is to let the default web browser open any link that the user might click inside the WebView. However, this default logic can be modified by configuring a `WebViewClient` which allows navigation requests to be handled by the app itself.

## Steps

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

## Dynamic Analysis

A convenient way to dynamically test deep linking is to use Frida or frida-trace and hook the `shouldOverrideUrlLoading`, `shouldInterceptRequest` methods while using the app and clicking on links within the WebView. Be sure to also hook other related [`Uri`](https://developer.android.com/reference/android/net/Uri "Uri class") methods such as `getHost`, `getScheme` or `getPath` which are typically used to inspect the requests and match known patterns or deny lists.
