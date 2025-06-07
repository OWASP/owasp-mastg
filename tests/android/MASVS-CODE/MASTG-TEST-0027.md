---
masvs_v1_id:
- MSTG-PLATFORM-2
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: Testing for URL Loading in WebViews
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

In order to test for [URL loading in WebViews](../../../Document/0x05h-Testing-Platform-Interaction.md#url-loading-in-webviews "URL Loading in WebViews") you need to carefully analyze [handling page navigation](https://developer.android.com/guide/webapps/webview#HandlingNavigation "Handling page navigation"), especially when users might be able to navigate away from a trusted environment. The default and safest behavior on Android is to let the default web browser open any link that the user might click inside the WebView. However, this default logic can be modified by configuring a `WebViewClient` which allows navigation requests to be handled by the app itself.

## Static Analysis

### Check for Page Navigation Handling Override

To test if the app is overriding the default page navigation logic by configuring a `WebViewClient` you should search for and inspect the following interception callback functions:

- `shouldOverrideUrlLoading` allows your application to either abort loading WebViews with suspicious content by returning `true` or allow the WebView to load the URL by returning `false`. Considerations:
    - This method is not called for POST requests.
    - This method is not called for XmlHttpRequests, iFrames, "src" attributes included in HTML or `<script>` tags. Instead, `shouldInterceptRequest` should take care of this.
- `shouldInterceptRequest` allows the application to return the data from resource requests. If the return value is null, the WebView will continue to load the resource as usual. Otherwise, the data returned by the `shouldInterceptRequest` method is used. Considerations:
    - This callback is invoked for a variety of URL schemes (e.g., `http(s):`, `data:`, `file:`, etc.), not only those schemes which send requests over the network.
    - This is not called for `javascript:` or `blob:` URLs, or for assets accessed via `file:///android_asset/` or `file:///android_res/` URLs.
  In the case of redirects, this is only called for the initial resource URL, not any subsequent redirect URLs.
    - When Safe Browsing is enabled, these URLs still undergo Safe Browsing checks but the developer can allow the URL with `setSafeBrowsingWhitelist` or even ignore the warning via the `onSafeBrowsingHit` callback.

As you can see there are a lot of points to consider when testing the security of WebViews that have a WebViewClient configured, so be sure to carefully read and understand all of them by checking the [`WebViewClient` Documentation](https://developer.android.com/reference/android/webkit/WebViewClient "WebViewClient").

### Check for EnableSafeBrowsing Disabled

While the default value of `EnableSafeBrowsing` is `true`, some applications might opt to disable it. To verify that SafeBrowsing is enabled, inspect the AndroidManifest.xml file and make sure that the configuration below is not present:

```xml
<manifest>
    <application>
        <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing"
                   android:value="false" />
        ...
    </application>
</manifest>
```

## Dynamic Analysis

A convenient way to dynamically test deep linking is to use Frida or frida-trace and hook the `shouldOverrideUrlLoading`, `shouldInterceptRequest` methods while using the app and clicking on links within the WebView. Be sure to also hook other related [`Uri`](https://developer.android.com/reference/android/net/Uri "Uri class") methods such as `getHost`, `getScheme` or `getPath` which are typically used to inspect the requests and match known patterns or deny lists.
