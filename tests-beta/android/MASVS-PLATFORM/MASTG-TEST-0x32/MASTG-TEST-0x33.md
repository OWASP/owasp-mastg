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

Many apps let users view web content using a WebView. WebViews can load content from various sources, including local files using several methods from the [`WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings.html) class, such as `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, and `setAllowUniversalAccessFromFileURLs`. The location from which the HTML file is loaded must be verified. If the file is loaded from external storage, for example, the file is readable and writable by everyone. This is considered a bad practice. Instead, the file should be placed in the app's assets directory.

For attacks related to these APIs to be successful, JavaScript must be enabled in the WebView.

This test checks for references to the aforementioned methods in the `WebSettings` class. These methods control file access within a WebView and can be used to access local files.

- **setAllowFileAccess(true)** opens the door for the WebView to load local files.
- **setAllowFileAccessFromFileURLs(true)** lets JavaScript within those local files access other local files.
- **setAllowUniversalAccessFromFileURLs(true)** removes any cross-origin restrictions, allowing that JavaScript to both read files and transmit data across origins.

By combining these settings, an attack can become possible because if a malicious HTML file gains full privilege and it's able to access local resources and then exfiltrate them over the network, effectively bypassing the usual security barriers enforced by the same-origin policy.

**Attack Scenario:**

Suppose a banking app uses a WebView to display dynamic content, and the developers enabled all three insecure settings.

An attacker manages to inject a malicious HTML file into the device (via phishing or another exploit). Because of the enabled settings:

1. The WebView loads the malicious file (thanks to `setAllowFileAccess(true)`).  
2. The JavaScript in that file, now running in a `file://` context, can access other sensitive local files (via `setAllowFileAccessFromFileURLs(true)`).  
3. Finally, the script can bypass cross-origin restrictions (`setAllowUniversalAccessFromFileURLs(true)`) and send the stolen data to an attacker-controlled server.

This combination effectively turns the WebView into a powerful tool for data exfiltration, exposing sensitive information from the device.

## Steps

1. Use a tool like semgrep to search for references to the `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, and `setAllowUniversalAccessFromFileURLs` methods in the `WebSettings` class.
2. Determine if JavaScript is enabled in the WebView by checking the value of `setJavaScriptEnabled`.

## Observation

The output should contain a list of locations where these methods are used. For each location, check whether:

- the method is used and explicitly set to `true`.
- the method is used and explicitly set to `false`.
- the method is not used and the default value is assumed.

Note that the value of `setAllowFileAccessFromFileURLs` [**is ignored**](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean)) if the value of `allowUniversalAccessFromFileURLs` is `true`.

## Evaluation

The test fails if any of the methods are used and explicitly set to `true` or if the default value is assumed.

The test passes if all relevant methods are used and explicitly set to `false`.

Mitigations include:

In general, for modern Android versions (API level 30 and above), the default values for these methods are secure and some of these methods are deprecated. However, the app must be configured with a `minSdkVersion` that has secure defaults for these methods.

- For apps with a `minSdkVersion` that has secure defaults for these methods, ensure that the methods are **not used** and the default values are assumed.
- For apps with a `minSdkVersion` that **does not have secure defaults** for these methods, ensure that the methods are used and **explicitly** set to `false`.

To load file content to a WebView securely, use [`WebViewClient`](https://developer.android.com/reference/android/webkit/WebViewClient) with [`WebViewAssetLoader`](https://developer.android.com/reference/androidx/webkit/WebViewAssetLoader) to load assets from the app's assets directory using `https://` instead of `file://` URLs.

Note that some apps may require these methods to be set to `true` for legitimate reasons. In such cases, ensure that the app follows best practices to prevent misuse. For example:

- the WebView does not load files from external storage and should instead place them in the app's assets directory.
- the WebView validates and sanitizes all input to prevent script injection.

If not required, disable JavaScript in the WebView by setting [`setJavaScriptEnabled`](https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled%28boolean%29) to `false`.
