---
platform: android
title: References to Content Provider Access in WebViews
alias: references-to-content-provider-access-in-webviews
id: MASTG-TEST-0x32
apis: [WebView, ContentProvider, allowContentAccess]
type: [static]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013]
---

## Overview

This test checks for references to Content Provider access in WebViews which is enabled by default and can be disabled using the `setAllowContentAccess` method in the `WebSettings` class. If improperly configured, this can introduce security risks such as unauthorized file access and data exfiltration.

The JavaScript code would have access to any content provider on the device, **including those declared by the app as not exported** and **others that are exported by other apps** and may not be following the recommended [best practices](https://developer.android.com/privacy-and-security/security-tips#content-providers).

Refer to [WebView Content Provider Access](../../../Document/0x05h-Testing-Platform-Interaction.md/#webview-content-provider-access) for more information on the `setAllowContentAccess` method, the specific files that can be accessed and the conditions under which they can be accessed.

The `setAllowContentAccess` method being set to `true` is not a security issue by itself, but it can be used in combination with other vulnerabilities to escalate the impact of an attack. Therefore, it is recommended to explicitly set it to `false` if the app does not need to access content providers.

**Example Attack Scenario:**

Suppose a banking app uses a WebView to display dynamic content. The developers have not explicitly set the `setAllowContentAccess` method, so it defaults to `true`. Additionally, JavaScript is enabled in the WebView.

1. An attacker exploits a vulnerability (such as an XSS flaw) to inject malicious JavaScript into the WebView. This could occur through a compromised or malicious link that the WebView loads without proper validation.
2. The malicious JavaScript issues requests to `content://` URIs to read locally stored files or data exposed by content providers. Even those content providers from the app that are not exported can be accessed because the malicious code is running in the same process and same origin as the trusted code.
3. The attacker-controlled script exfiltrates sensitive data from the device to an external server.


TO BE CONFIRMED!!!!

The provider must also be declared with `android:grantUriPermissions="true"` in the manifest. This is necessary because the provider is not exported, and the app must have the necessary permissions to access the content.

## Steps

1. Use a tool like semgrep to search for references to:
      - the `WebView` class.
      - the `WebSettings` class.
      - the `setJavaScriptEnabled` method.
      - the `setAllowContentAccess` method from the `WebSettings` class.
2. Obtain all content providers declared in the app's AndroidManifest.xml file.
3. Check if the `android:grantUriPermissions="true"` attribute is set for each content provider.  TO BE CONFIRMED!!!!

## Observation

The output should contain:

- A list of WebView instances where the `setAllowContentAccess` method is used or not used at all (inheriting the default value, `true`).
- A list of content providers declared in the app's AndroidManifest.xml file.
- A list of content providers that have the `android:grantUriPermissions="true"` attribute set.

## Evaluation

The test fails if all of the following are true:

- The `setJavaScriptEnabled` method is explicitly set to `true`.
- The `setAllowContentAccess` method is explicitly set to `true` or not used at all (inheriting the default value, `true`).

The test passes if all of the following are true:

- The `setJavaScriptEnabled` method is explicitly set to `false` or not used at all (inheriting the default value, `false`).
- The `setAllowContentAccess` method is explicitly set to `false`.

Note that we do not even consider `minSdkVersion` since `setAllowContentAccess` defaults to `true` regardless of the Android version and `setAllowUniversalAccessFromFileURLs` defaults to `false` since API level 16 (Android 4.1 from 2012).
