---
masvs_v1_id:
- MSTG-PLATFORM-5
masvs_v2_id:
- MASVS-PLATFORM-2
platform: android
title: Testing JavaScript Execution in WebViews
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: []
deprecation_note: Having JavaScript enabled is not considered a vulnerability by itself, but it can lead to security issues in combination with other weaknesses, such as local file access in WebViews, which are covered by other tests in the MASTG v2. This test is therefore not considered a standalone test anymore.
---

## Overview

To test for [JavaScript execution in WebViews](../../../Document/0x05h-Testing-Platform-Interaction.md#javascript-execution-in-webviews "JavaScript Execution in WebViews") check the app for WebView usage and evaluate whether or not each WebView should allow JavaScript execution. If JavaScript execution is required for the app to function normally, then you need to ensure that the app follows the all best practices.

## Static Analysis

To create and use a WebView, an app must create an instance of the `WebView` class.

```java
WebView webview = new WebView(this);
setContentView(webview);
webview.loadUrl("https://www.owasp.org/");
```

Various settings can be applied to the WebView (activating/deactivating JavaScript is one example). JavaScript is disabled by default for WebViews and must be explicitly enabled. Look for the method [`setJavaScriptEnabled`](https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled%28boolean%29 "setJavaScriptEnabled in WebViews") to check for JavaScript activation.

```java
webview.getSettings().setJavaScriptEnabled(true);
```

This allows the WebView to interpret JavaScript. It should be enabled only if necessary to reduce the attack surface to the app. If JavaScript is necessary, you should make sure that

- The communication to the endpoints consistently relies on HTTPS (or other protocols that allow encryption) to protect HTML and JavaScript from tampering during transmission.
- JavaScript and HTML are loaded locally, from within the app data directory or from trusted web servers only.
- The user cannot define which sources to load by means of loading different resources based on a user provided input.

To remove all JavaScript source code and locally stored data, clear the WebView's cache with [`clearCache`](https://developer.android.com/reference/android/webkit/WebView#clearCache%28boolean%29 "clearCache in WebViews") when the app closes.

Devices running platforms older than Android 4.4 (API level 19) use a version of WebKit that has several security issues. As a workaround, the app must confirm that WebView objects [display only trusted content](https://developer.android.com/training/articles/security-tips.html#WebView "WebView Best Practices") if the app runs on these devices.

## Dynamic Analysis

Dynamic Analysis depends on operating conditions. There are several ways to inject JavaScript into an app's WebView:

- Stored Cross-Site Scripting vulnerabilities in an endpoint; the exploit will be sent to the mobile app's WebView when the user navigates to the vulnerable function.
- Attacker takes a [Machine-in-the-Middle (MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) position and tampers with the response by injecting JavaScript.
- Malware tampering with local files that are loaded by the WebView.

To address these attack vectors, check the following:

- All functions offered by the endpoint should be free of [stored XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting "Stored Cross-Site Scripting").
- Only files that are in the app data directory should be rendered in a WebView (see test case "Testing for Local File Inclusion in WebViews").

- The HTTPS communication must be implemented according to best practices to avoid MITM attacks. This means:
    - all communication is encrypted via TLS,
    - the certificate is checked properly, and/or
    - the certificate should be pinned.
