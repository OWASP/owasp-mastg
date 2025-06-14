---
title: Incorrect Implementation of Server Hostname Verification
platform: android
id: MASTG-TEST-0234-2
type: [static]
weakness: MASWE-0052
---

## Overview

Using [`HostnameVerifier.verify()`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.SSL.SSLSession)) is a good practise (especially in cases when it's not automatically done, such as [when using the `SSLSocket` API](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket). However, when used and [implemented in an unsafe manner](https://developer.android.com/privacy-and-security/risks/unsafe-hostname) such as:

- overriding `verify(...)` to unconditionally return `true`
- applying overly-broad wildcard rules
- forgetting to invoke your verifier on *every* SSL/TLS channel (e.g. after renegotiation or on a raw `SSLSocket`)
- etc.

In these cases, the app effectively turns off hostname validation for the affected connections. In this state, the app will accept any certificate for any host, allowing an attacker to run a [MITM attack](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) with a valid (or self-signed) certificate and intercept or tamper with the app's traffic.

## Steps

1. Reverse engineer (@MASTG-TECH-0017) the app (@MASTG-APP-0018).
2. Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `X509HostnameVerifier` and `HostnameVerifier`.

## Observation

You will find the `HostnameVerifier` used as an interface for a `synthetic constructor` within the `MainActivity` smali file. This synthetic class only has a constructor that return void indicating that the `HostnameVerifier` does not verify the host as it should. In the same file, you will also find the `X509HostnameVerifier` called `ALLOW_ALL_HOSTNAME_VERIFIER`. As the name indicate, it does not do any host name verification.

## Evaluation

The test case fails if hostname verification is missing or implemented incorrectly.
