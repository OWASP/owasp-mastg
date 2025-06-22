---
title: Incorrect Implementation of Server Hostname Verification
platform: android
id: MASTG-TEST-0283
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
---

## Overview

This test evaluates whether an Android app implements a [`HostnameVerifier`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier) that uses [`verify(...)`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.SSL.SSLSession)) [in an unsafe manner](https://developer.android.com/privacy-and-security/risks/unsafe-hostname), effectively turning off hostname validation for the affected connections.

Such unsafe implementations can allow an attacker to run a [MITM attack](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) with a valid (or self-signed) certificate and intercept or tamper with the app's traffic.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `HostnameVerifier`.

## Observation

The output contains a list of locations where `HostnameVerifier` is used.

## Evaluation

The test fails if the app does **not** properly validate that the server's hostname matches the certificate.

This includes cases such as:

- **Always accepting hostnames:** overriding `verify(...)` to unconditionally return `true`, regardless of the actual hostname or certificate.
- **Overly broad matching rules:** using permissive wildcard logic that matches unintended domains.
- **Incomplete verification coverage:** failing to invoke hostname verification on all SSL/TLS channels, such as those created via `SSLSocket`, or during renegotiation.
- **Missing manual verification:** not performing hostname verification when it is not done automatically, such as when using the low-level `SSLSocket` API.

When testing using automated tools, you will need to inspect all the reported locations in the reverse-engineered code to confirm the incorrect implementation (@MASTG-TECH-0023).
