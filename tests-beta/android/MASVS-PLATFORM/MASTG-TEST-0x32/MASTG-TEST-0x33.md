---
platform: android
title: References to Local File Access in WebViews
alias: references-to-local-file-access-in-webviews
id: MASTG-TEST-0x33
apis: [WebView, setAllowFileAccess, setAllowFileAccessFromFileURLs, setAllowUniversalAccessFromFileURLs]
type: [static]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0010, MASTG-BEST-0011, MASTG-BEST-0012]
---

## Overview

This test checks for references to methods from the [`WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings.html) class used by Android WebViews which [enable loading content from various sources, including local files](../../../Document/0x05h-Testing-Platform-Interaction/#webview-local-file-access-settings). If improperly configured, these methods can introduce security risks such as unauthorized file access and data exfiltration. These methods are:

- `setAllowFileAccess`: allows the WebView to load local files from the app's internal storage or external storage.
- `setAllowFileAccessFromFileURLs`: lets JavaScript within those local files access other local files.
- `setAllowUniversalAccessFromFileURLs`: removes any cross-origin restrictions, allowing that JavaScript to both read files and transmit data across origins.

By combining these settings, an attack can become possible because if a malicious HTML file gains full privilege and it's able to access local resources and then exfiltrate them over the network, effectively bypassing the usual security barriers enforced by the same-origin policy.

Even though these methods have secure defaults and are **deprecated in Android 10 (API level 29) and later**, they can still be explicitly set to `true` or use their insecure defaults in apps that can run in older versions of Android (due to their `minSdkVersion`).

Refer to [Android WebView Local File Access Settings](../../../Document/0x05h-Testing-Platform-Interaction/#webview-local-file-access-settings) for more information on the these methods (default values, deprecation status, security implications), the specific files that can be accessed and the conditions under which they can be accessed.

**Example Attack Scenario**:

Suppose a banking app uses a WebView to display dynamic content, and the developers enabled all three insecure settings.

1. An attacker injects a malicious HTML file into the device (via phishing or another exploit) into a location that the attacker _knows_ (e.g. thanks to reverse engineering) the WebView will access.
2. The WebView loads the malicious file because `setAllowFileAccess(true)` is enabled.
3. The JavaScript in the malicious file (running in a `file://` context) is able to access other local files using `file://` URLs, enabled by `setAllowFileAccessFromFileURLs(true)`.
4. The JavaScript is also able to bypass cross-origin restrictions thanks to `setAllowUniversalAccessFromFileURLs(true)`.
5. The attacker-controlled script exfiltrates sensitive data from the device to an external server.

## Steps

1. Determine the `minSdkVersion` of the app.
2. Use a tool like semgrep to search for references to:
      - the `WebView` class.
      - the `WebSettings` class.
      - the `setJavaScriptEnabled` method.
      - the `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, and `setAllowUniversalAccessFromFileURLs` methods from the `WebSettings` class.

Note that in this case **the lack of references to the `setAllow*` methods is especially interesting** and must be captured, because it could mean that the app is using the default values, which in some scenarios are insecure. For this reason, it's highly recommended to try to identify every WebView instance in the app.

## Observation

The output should contain a list of WebView instances where the abovementioned methods are used.

## Evaluation

The evaluation of this test is based on the [API behavior across different Android versions](../../../Document/0x05h-Testing-Platform-Interaction/#webview-local-file-access-settings).

The test fails if:

- The `setJavaScriptEnabled` method is explicitly set to `true`.
- Any of the methods are explicitly set to `true`.
- The default value is assumed (the methods aren't explicitly used) and:
    - `minSdkVersion` < 30 for `setAllowFileAccess`.
    - `minSdkVersion` < 16 for `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`.

The test passes if:

- The `setJavaScriptEnabled` method is explicitly set to `false` or not used at all (inheriting the default value, `false`).
- All relevant methods are explicitly set to `false`.
- The default value is assumed (the methods aren't explicitly used) and:
    - `minSdkVersion` >= 30 for `setAllowFileAccess`.
    - `minSdkVersion` >= 16 for `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`.
