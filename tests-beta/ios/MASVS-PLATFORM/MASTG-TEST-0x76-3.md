---
platform: ios
title: URI Manipulation in WebView 
id: MASTG-TEST-0x76-3
type: [static]
weakness: MASWE-0071
---

## Overview

The target URL of a [`WkWebView`](https://developer.apple.com/documentation/webkit/wkwebview "Apple Developer") can be set dynamically, for example via the [load](https://developer.apple.com/documentation/webkit/wkwebview/1414954-load "Apple Developer") method. This will load the corresponding content into the view.

The `WkWebView` can be tricked into showing malicious content if this URL can be controlled by an attacker. The input must be properly sanitized to avoid this issue.

## Steps

1. Extract the app as described in @MASTG-TECH-0058.
2. Review the code or reverse engineer the binary according to @MASTG-TECH-0076 and identify data flows from attacker-controlled input to the load method of `WkWebView`.

## Observation

The output could contain [load operations](https://developer.apple.com/documentation/webkit/wkwebview "Apple Developer") where the URL in the [`URLRequest`](https://developer.apple.com/documentation/foundation/urlrequest?language=objc "Apple Developer") is not hard-coded.

## Evaluation

The test case fails if an attacker-controlled input is passed into a load operation without being sanitized.

The URL should not depend on dynamic input. If this is not avoidable, the input must be sanitized. For example, the app must ensure that only URLs with a set of well-known domains are loaded.
