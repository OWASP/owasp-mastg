---
title: Debugging Enabled for WebViews
platform: android
id: MASTG-TEST-0227
type: [static]
weakness: MASWE-0067
best-practices: [MASTG-BEST-0008]
profiles: [R]
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
