---
title: SSLSockets not Properly Verifying Hostnames
platform: android
id: MASTG-TEST-0234
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
---

## Overview

`SSLSocket` does not perform hostname verification by default unless the app explicitly uses [`HostnameVerifier.verify()`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.SSL.SSLSession)). See the ["Android documentation"](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket) and ["Unsafe HostnameVerifier"](https://developer.android.com/privacy-and-security/risks/unsafe-hostname) for more details.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `SSLSocket` and `HostnameVerifier`.

## Observation

The output contains a list of locations where `SSLSocket` and `HostnameVerifier` are used.

## Evaluation

The test case fails if hostname verification is missing or implemented incorrectly.
