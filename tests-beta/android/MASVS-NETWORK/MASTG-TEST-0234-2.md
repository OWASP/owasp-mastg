---
title: Incorrect Implementation of Server Hostname Verification
platform: android
id: MASTG-TEST-0234-2
type: [static]
weakness: MASWE-0052
---

## Overview

This test evaluates whether an Android app uses [`HostnameVerifier.verify()`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify(java.lang.String,%20javax.net.SSL.SSLSession)) [in an unsafe manner](https://developer.android.com/privacy-and-security/risks/unsafe-hostname), effectively turning off hostname validation for the affected connections.
	
Such unsafe implementations can allow an attacker to run a [MITM attack](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) with a valid (or self-signed) certificate and intercept or tamper with the app's traffic.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Inspect the source code and run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `X509HostnameVerifier` and `HostnameVerifier`.

## Observation

The output contains a list of locations where `HostnameVerifier` or `X509HostnameVerifier` are used.

## Evaluation

The test case fails if hostname verification is present but implemented incorrectly, e.g. by unconditionally returning `true`.

When testing using automated tools, you will need to inspect all the reported locations in the reverse-engineered code to confirm the incorrect implementation (@MASTG-TECH-0023).
