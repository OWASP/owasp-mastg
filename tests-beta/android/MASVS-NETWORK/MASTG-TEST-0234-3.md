---
title: Correct use of SSL error handling for webviews
platform: android
id: MASTG-TEST-0234-2
type: [static]
weakness: MASWE-0052
---

## Overview

Inside `onReceivedSslError` if no exceptions are thrown and there is a `handler.proceed()` call, TLS errors are muted. 

## Steps

1. Reverse engineer (@MASTG-TECH-0017) the app (@MASTG-APP-0018).
2. Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `onReceivedSslError`.

## Observation

You will find the public method `onReceivedSslError` within the `MainActivity` smali file. There are calls to null checks for each of the parameters `view`, `handler` and `error` as required by the method signature. Several if statements follows, but none of them does more then initializing strings. There are also invocations of two static log functions `w` denoted by `invoke-static`.
At the end there is a invocation of a `SslErrorHandler` named `proceed` and a `return-void` statement which indicate that the `handler.proceed()` is called without returning anything from the function. Nowhere, within the method, is there any indication that there are exception handling that properly handles TLS errors.

## Evaluation

The test case fails if `onReceivedSslError` together with `handler.proceed()` without proper exception handling.
