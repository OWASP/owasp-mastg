---
title: Incorrect SSL Error Handling in WebViews
platform: android
id: MASTG-TEST-0234-3
type: [static]
weakness: MASWE-0052
---

## Overview

Inside `onReceivedSslError` if no exceptions are thrown and there is a `handler.proceed()` call, TLS errors are muted.

## Steps

1. Reverse engineer (@MASTG-TECH-0017) the app (@MASTG-APP-0018).
2. Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `onReceivedSslError`.

## Observation

The output contains a list of locations where `onReceivedSslError` that includes a `handler.proceed()` is used without exception handling that properly handles TLS errors.

## Evaluation

The test case fails if `onReceivedSslError` is used together with `handler.proceed()` without proper exception handling.

When testing using automated tools, you will need to inspect all the reported locations in the reverse-engineered code to confirm the incorrect implementation (@MASTG-TECH-0023).
