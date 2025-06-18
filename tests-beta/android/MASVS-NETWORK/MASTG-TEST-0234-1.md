---
title: Incorrect implementation of server certificate verification
platform: android
id: MASTG-TEST-0234-1
type: [static]
weakness: MASWE-0052
---

## Overview

This test evaluates whether an Android app uses [`X509TrustManager.checkServerTrusted()`](https://developer.android.com/reference/javax/net/ssl/X509TrustManager#checkServerTrusted%28java.security.cert.X509Certificate[],%20java.lang.String%29) [in an unsafe manner](https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager) as part of a custom `TrustManager`, causing any connection configured to use that `TrustManager` to skip certificate validation.

Such unsafe implementations can allow an attacker to run a [MITM attack](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) with a valid (or self-signed) certificate and intercept or tamper with the app's traffic.

## Steps

1. Reverse engineer (@MASTG-TECH-0017) the app (@MASTG-APP-0018).
2. Run a static analysis (@MASTG-TECH-0014) tool for the app (@MASTG-APP-0018) and look for all usages of `checkServerTrusted`.

## Observation

The output contains a list of locations where `checkServerTrusted` is used.

## Evaluation

The test fails if there is no indication of a `CertificateException` being throw except through the method signature.
