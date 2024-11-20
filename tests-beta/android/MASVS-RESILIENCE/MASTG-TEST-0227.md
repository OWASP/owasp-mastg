---
title: Debugging Enabled for WebViews
platform: android
id: MASTG-TEST-0227
type: [static]
weakness: MASWE-0067
---

## Overview

To enable debugging of Webviews, the API `WebView.setWebContentsDebuggingEnabled(true);` can be used to enable WebView debugging (see the ["Android documentation"](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging)).

Calling this API will enable WebView debugging for **all** of the application's WebViews allowing an attached PC to eavesdrop on, and modify all communication inside WebViews.

This flag works independently of the AndroidManifest.xml debuggable flag (see @MASTG-TEST-0226), so even if the app is not debuggable, the WebViews can be debuggable.

!!! note Other ways to debug the application
    Disabling WebView debugging does not fully prevent all possibilities to debug the app and the WebViews. See @MASWE-0101 for more details on how to prevent debugging.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary and look for uses of:
    - `WebView.setWebContentsDebuggingEnabled` being set to `true`.
    - `ApplicationInfo.FLAG_DEBUGGABLE`.

## Observation

The output should contain all locations where `WebView.setWebContentsDebuggingEnabled` can be called with `true` at runtime as well as any uses of `ApplicationInfo.FLAG_DEBUGGABLE`.

## Evaluation

The test case fails if there are any instances of WebView debugging being enabled and they can be always executed at runtime (meaning that the app does not check for the `ApplicationInfo.FLAG_DEBUGGABLE`).

To mitigate this issue you can set the `WebView.setWebContentsDebuggingEnabled` calls to `false` or completely remove them altogether.

If you want to enable WebView debugging only when debuggable is `true`, Android recommends [checking the debuggable flag at runtime](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging):

```kotlin
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    if (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE))
    { WebView.setWebContentsDebuggingEnabled(true); }
}
```
