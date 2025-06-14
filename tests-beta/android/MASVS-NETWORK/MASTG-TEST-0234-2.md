---
title: Incorrect Implementation of Server Hostname Verification
platform: android
id: MASTG-TEST-0234-2
type: [static]
weakness: MASWE-0052
---

## Overview

`SSLSocket` does not perform hostname verification by default unless the app explicitly uses [`HostnameVerifier.verify()`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.SSL.SSLSession)). See the ["Android documentation"](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket) and ["Unsafe HostnameVerifier"](https://developer.android.com/privacy-and-security/risks/unsafe-hostname) for more details.

## Steps

1. Reverse engineer (@MASTG-TECH-0017) the app (@MASTG-APP-0018).
2. Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `X509HostnameVerifier` and `HostnameVerifier`.

## Observation

You will find the `HostnameVerifier` used as an interface for a `synthetic constructor` within the `MainActivity` smali file. This synthetic class only has a constructor that return void indicating that the `HostnameVerifier` does not verify the host as it should. In the same file, you will also find the `X509HostnameVerifier` called `ALLOW_ALL_HOSTNAME_VERIFIER`. As the name indicate, it does not do any host name verification.

## Evaluation

The test case fails if hostname verification is missing or implemented incorrectly.
