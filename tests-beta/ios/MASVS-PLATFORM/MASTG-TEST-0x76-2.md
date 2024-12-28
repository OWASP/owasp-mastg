---
platform: ios
title: JavaScript Enabled in WKWebView
id: MASTG-TEST-0x76-2
type: [static]
weakness: MASWE-0070
---

## Overview

[`WKWebView`](https://developer.apple.com/documentation/webkit/wkwebview "Apple Developer")offers the `javaScriptEnabled` and `allowsContentJavaScript` settings to disable all JavaScript execution. Disabling them avoids all [script injection flaws](../../../Document/0x06h-Testing-Platform-Interaction.md "iOS Platform APIs").

## Steps

1. Extract the app as described in @MASTG-TECH-0058.
2. Review the code or reverse engineer the binary according to @MASTG-TECH-0076 and identify references to `WkWebView`, calls to `WkPreferences.javaScriptEnabled` and
   `WKWebPagePreferences.allowsContentJavaScript`.

## Observation

The output could contain references to `WkWebView` or calls to `WkPreferences.javaScriptEnabled` and `WKWebPagePreferences.allowsContentJavaScript`.

## Evaluation

The test case fails if there are references to `WkWebView` and one of the following is true:

- There are no references to `WkPreferences.javaScriptEnabled` or `defaultWebpagePreferences.allowsContentJavaScript`.
- `WkPreference.javaScriptEnabled` is set to `1`.
- `WKWebpagePreferences.allowsContentJavaScript` is set to `1`.

The preferences should be set to `NO` (0), so that JavaScript is not executed in the `WkWebView` to avoid possible script injections.
