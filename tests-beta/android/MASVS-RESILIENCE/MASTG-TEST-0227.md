---
title: Debugging Enabled for WebViews
platform: android
id: MASTG-TEST-0227
type: [static]
weakness: MASWE-0067
---

## Overview

The `WebView.setWebContentsDebuggingEnabled(true)` API enables debugging for **all** WebViews in the application. This feature can be useful during development, but introduces significant security risks if left enabled in production. When enabled, a connected PC can debug, eavesdrop, or modify communication within any WebView in the application. See the ["Android Documentation"](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging) for more details.

Note that this flag works independently of the `debuggable` attribute in the `AndroidManifest.xml` (see @MASTG-TEST-0226). Even if the app is not marked as debuggable, the WebViews can still be debugged by calling this API.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary and look for uses of:
    - `WebView.setWebContentsDebuggingEnabled` being set to `true`.
    - `ApplicationInfo.FLAG_DEBUGGABLE`.

## Observation

The output should list:

- All locations where `WebView.setWebContentsDebuggingEnabled` is called with `true` at runtime.
- Any references to `ApplicationInfo.FLAG_DEBUGGABLE`.

## Evaluation

The test case fails if `WebView.setWebContentsDebuggingEnabled(true)` is called unconditionally or in contexts where the `ApplicationInfo.FLAG_DEBUGGABLE` flag is not checked.

To mitigate this issue:

- Set `WebView.setWebContentsDebuggingEnabled` to `false` in production, or remove the calls entirely if they are unnecessary.
- If WebView debugging is required during development, ensure it is enabled only when the app is in a debuggable state by [checking the `ApplicationInfo.FLAG_DEBUGGABLE` flag at runtime](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging).

For example:

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE))
    { WebView.setWebContentsDebuggingEnabled(true); }
}
```

**Note:** Disabling WebView debugging this way helps protect an app already running on a device. For an attacker to exploit WebView debugging, they must have physical access to the device (e.g., a stolen or test device) or remote access through malware or other malicious means. Additionally, the device must typically be unlocked, and the attacker would need to know the device PIN, password, or biometric authentication to gain full control and connect debugging tools like `adb` or Chrome DevTools.

However, disabling WebView debugging does not eliminate all attack vectors. An attacker could:

1. Patch the app to add calls to these APIs (see @MASTG-TECH-0038), then repackage and re-sign it (see @MASTG-TECH-0039).
2. Use runtime method hooking (see @MASTG-TECH-0043) to enable WebView debugging dynamically at runtime.

Disabling WebView debugging serves as one layer of defense to reduce risks but should be combined with other security measures.
