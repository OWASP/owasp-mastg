---
platform: android
title: References to Local File Access in WebViews
alias: references-to-local-file-access-in-webviews
id: MASTG-TEST-0x33
apis: [WebView, setAllowFileAccess, setAllowFileAccessFromFileURLs, setAllowUniversalAccessFromFileURLs]
type: [static]
weakness: MASWE-0069
best-practices: []
---

## Overview

This test checks for references to methods from the [`WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings.html) class used by Android WebViews which enable loading content from various sources, including local files. These methods are:

- `setAllowFileAccess(true)` opens the door for the WebView to load local files.
- `setAllowFileAccessFromFileURLs(true)` lets JavaScript within those local files access other local files.
- `setAllowUniversalAccessFromFileURLs(true)` removes any cross-origin restrictions, allowing that JavaScript to both read files and transmit data across origins.

By combining these settings, an attack can become possible because if a malicious HTML file gains full privilege and it's able to access local resources and then exfiltrate them over the network, effectively bypassing the usual security barriers enforced by the same-origin policy.

Even though these methods have secure defaults and are deprecated in Android 10 (API level 29) and later, they can still be explicitly set to `true` or use their insecure defaults in apps that can run in older versions of Android (due to their `minSdkVersion`).

**Example Attack Scenario:**

Suppose a banking app uses a WebView to display dynamic content, and the developers enabled all three insecure settings.

An attacker manages to inject a malicious HTML file into the device (via phishing or another exploit). Because of the enabled settings:

1. The WebView loads the malicious file (thanks to `setAllowFileAccess(true)`).  
2. The JavaScript in that file, now running in a `file://` context, can access other sensitive local files (via `setAllowFileAccessFromFileURLs(true)`).  
3. Finally, the script can bypass cross-origin restrictions (`setAllowUniversalAccessFromFileURLs(true)`) and send the stolen data to an attacker-controlled server.

This combination effectively turns the WebView into a powerful tool for data exfiltration, exposing sensitive information from the device.

## Steps

1. Determine the `minSdkVersion` of the app.
2. Use a tool like semgrep to search for references to the `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, and `setAllowUniversalAccessFromFileURLs` methods in the `WebSettings` class.
3. Determine if JavaScript is enabled in the WebView by checking the value of `setJavaScriptEnabled`.

## Observation

The output should contain a list of locations where these methods are used. For each location, check whether:

- the method is used and explicitly set to `true`.
- the method is used and explicitly set to `false`.
- the method is not used and the default value is assumed.

Note that the value of `setAllowFileAccessFromFileURLs` [**is ignored**](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean)) if the value of `allowUniversalAccessFromFileURLs` is `true`.

## Evaluation

The test fails if any of the methods are used and explicitly set to `true` or if the default value is assumed.

The test passes if all relevant methods are used and explicitly set to `false`.

## Mitigations

**Update the app's `minSdkVersion`:**

In general, for modern Android versions (API level 30 and above), the default values for these methods are secure and some of these methods are deprecated (`setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`). However, the app must be configured with a `minSdkVersion` that has secure defaults for these methods. In some cases, `minSdkVersion` cannot be increased due to compatibility reasons to support older devices.

**Use secure defaults and explicit disablement:**

- For apps with a `minSdkVersion` that has secure defaults for these methods, ensure that the methods are **not used** and the default values are assumed. Alternatively, explicitly set the methods to `false` to ensure that the WebView does not load local files in any case.
- For apps with a `minSdkVersion` that **does not have secure defaults** for these methods, ensure that the methods are used and **explicitly** set to `false`.

**Securely load file content to a WebView:**

The recommended approach to **load file content to a WebView securely** is to use [`WebViewClient`](https://developer.android.com/reference/android/webkit/WebViewClient) with [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader) to load assets from the app's assets directory using `https://` instead of `file://` URLs.

**Disable JavaScript in the WebView:**

If not required, disable JavaScript in the WebView by setting [`setJavaScriptEnabled`](https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled%28boolean%29) to `false`.
