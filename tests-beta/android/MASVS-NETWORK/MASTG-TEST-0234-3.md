---
title: Incorrect SSL Error Handling in WebViews
platform: android
id: MASTG-TEST-0234-3
type: [static]
weakness: MASWE-0052
---

## Overview

The method [`WebViewClient.onReceivedSslError()`](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError%28android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError%29) is triggered when a `WebView` encounters an SSL certificate error while loading a page. By default, the `WebView` cancels the request to protect users from insecure connections. Overriding this method and calling [`SslErrorHandler.proceed()`](https://developer.android.com/reference/android/webkit/SslErrorHandler#proceed%28%29) without proper validation or user consent disables these protections.

This effectively bypasses SSL certificate checks in the `WebView`, exposing the app to [MITM attacks](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) using invalid, expired, or self-signed certificates.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `onReceivedSslError`.

## Observation

The output contains a list of locations where `onReceivedSslError` that includes a `handler.proceed()` is used without exception handling that properly handles TLS errors.

## Evaluation

The test case fails if `onReceivedSslError` is used together with `handler.proceed()` without proper exception handling.

When testing using automated tools, you will need to inspect all the reported locations in the reverse-engineered code to confirm the incorrect implementation (@MASTG-TECH-0023).
