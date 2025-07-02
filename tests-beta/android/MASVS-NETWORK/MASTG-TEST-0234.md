---
title: Missing Implementation of Server Hostname Verification with SSLSockets
platform: android
id: MASTG-TEST-0234
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
---

## Overview

This test checks whether an Android app uses [`SSLSocket`](https://developer.android.com/reference/javax/net/ssl/SSLSocket) without a [`HostnameVerifier`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier), allowing connections to servers presenting certificates with **wrong or invalid hostnames**.

By default, `SSLSocket` [does not perform hostname verification](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket). To enforce it, the app must explicitly invoke [`HostnameVerifier.verify()`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify%28java.lang.String,%20javax.net.ssl.SSLSession%29) and implement proper checks.

Such unsafe implementations can allow an attacker to run a [MITM attack](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) with a valid (or self-signed) certificate and intercept or tamper with the app's traffic.

**Note:** The connection succeeds even if the app has a fully secure Network Security Configuration (NSC) in place because `SSLSocket` is not affected by it.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `SSLSocket` and `HostnameVerifier`.

## Observation

The output contains a list of locations where `SSLSocket` and `HostnameVerifier` are used.

## Evaluation

The test case fails if the app uses `SSLSocket` without a `HostnameVerifier`.

**Note:** If a `HostnameVerifier` is present, ensure it's not implemented in an unsafe manner. See @MASTG-TEST-0283 for guidance.
