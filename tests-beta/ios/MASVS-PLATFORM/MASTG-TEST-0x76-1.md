---
platform: ios
title: Deprecated Usage of UIWebView
id: MASTG-TEST-0x76-1
type: [static]
weakness: MASWE-0072
---

## Overview

`UIWebView` was deprecated in iOS 12.0 in favor of `WKWebView` which is available since iOS 8.0. `WKWebView` offers [better control over its capabilities](../../../Document/0x06h-Testing-Platform-Interaction/#uiwebview "iOS Platform APIs: UIWebView"), e.g. it allows you to disable JavaScript with `javaScriptEnabled` and it can verify resources with the `hasOnlySecureContent`. Thus, it should be preferred over `UIWebView`.

In this test we can check any references to `UIWebView` inside the binary.

## Steps

1. Extract the app as described in @MASTG-TECH-0058.
2. Look for references to `UIWebView` in the app using @MASTG-TECH-0070 on all executables and libraries.

## Observation

The output shows function names and methods for the binaries.

## Evaluation

The test case fails if there are any references to `UIWebView`.
