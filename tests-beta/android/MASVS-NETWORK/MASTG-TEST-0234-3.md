---
title: Incorrect SSL Error Handling in WebViews
platform: android
id: MASTG-TEST-0234-3
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
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

The test fails if `onReceivedSslError(...)` is overridden and certificate errors are ignored without proper validation or user involvement.

This includes cases such as:

- **Unconditionally accepting SSL errors:** calling `handler.proceed()` without checking the nature of the error.
- **Relying only on primary error code:** using `error.getPrimaryError()` for decision-making, such as proceeding if the primary error is not `SSL_UNTRUSTED`, which may overlook additional errors in the chain.
- **Suppressing exceptions silently:** catching exceptions in `onReceivedSslError(...)` without calling `handler.cancel()`, which allows the connection to continue silently.

According to [official Android guidance](https://developer.android.com/reference/android/webkit/WebViewClient.html#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)), apps should never call `proceed()` in response to SSL errors. The correct behavior is to cancel the request to protect users from potentially insecure connections. User prompts are also discouraged, as users cannot reliably evaluate SSL issues.

When testing using automated tools, you will need to inspect all the reported locations in the reverse-engineered code to confirm the incorrect implementation (@MASTG-TECH-0023).
