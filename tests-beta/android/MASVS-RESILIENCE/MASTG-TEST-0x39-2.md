---
title: Debugging enabled for WebViews
platform: android
id: MASTG-TEST-0x39-2
type: [static]
weakness: MASWE-0067
---

## Overview

To enable debugging of Webviews, the API `WebView.setWebContentsDebuggingEnabled(true);` can be used to enable WebView debugging (see ["see Android documentation"](https://developer.chrome.com/docs/devtools/remote-debugging/webviews/#configure_webviews_for_debugging)).

Calling this API will enable WebView debugging for **all** of the application's WebViews, independently of the AndroidManifest.xml debuggable flag (See @MASTG-TEST-0x39-1). This allows an attached PC to eavesdrop on, and modify all communication inside WebViews.

!!! note Other ways to debug the application
    Disabling WebView debugging does not fully prevent all possibilities to debug the app and the WebViews. See @MASWE-0101 for more details on how to prevent debugging.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Inspect all locations where `WebView.setWebContentsDebuggingEnabled` is called, and check
    1. if it is set to true, and
    2. if the API call can be executed during runtime.

## Observation

The output should contain all locations where `WebView.setWebContentsDebuggingEnabled` can be called with `true` at runtime.

## Evaluation

The test case fails if any locations in the application can be executed ar runtime, where WebView debugging is enabled.
