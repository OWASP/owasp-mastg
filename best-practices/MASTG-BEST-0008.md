---
title: Debugging Disabled for WebViews
alias: debugging-disabled-webviews
id: MASTG-BEST-0008
platform: android
---

Ensure that WebView debugging is disabled in production builds to prevent attackers from exploiting this feature to eavesdrop, modify, or debug communication within WebViews.

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
