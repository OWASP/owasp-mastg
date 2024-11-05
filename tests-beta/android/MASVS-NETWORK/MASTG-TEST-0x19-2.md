---
title: SSLSockets not Properly Verifying Hostnames
platform: android
id: MASTG-TEST-0x19-2
type: [static]
weakness: MASWE-0052
---

## Overview

`SSLSocket` does not perform hostname verification (see ["Android documentation"](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket)) by default. This needs to be implemented securely by the app itself.

A secure way isto implement an own `HostnameVerifier` which forwards the hostname verification to the `verify()` method of the `DefaultHostnameVerifier()`Be aware that `HostnameVerifier.verify()` does not throw an exception on error. Instead, it returns a boolean result that must explicitly check by the app.

See ["Unsafe HostnameVerifier"](https://developer.android.com/privacy-and-security/risks/unsafe-hostname) for more information about insecure `HostnameVerifiers`.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `SSLSocket`.
3. Verify each `SSLSocket` attaches a `HostnameVerifier` and verify the implementation of the HostnameVerifier is secure.

## Observation

The output contains a list of locations where `SSLSocket` is used and does not perform hostname verification or does so incorrectly.

## Evaluation

The test case fails if any hostname verification is missing, or implemented insecurely.
