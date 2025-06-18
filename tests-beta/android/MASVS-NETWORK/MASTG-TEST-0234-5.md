---
title: Network Security Configuration Allowing Trust in User-Provided CAs
platform: android
id: MASTG-TEST-0234-5
type: [static]
weakness: MASWE-0052
---

## Overview

This test evaluates whether an Android app explicitly trusts user-added CA certificates by including [`<certificates src="user"/>`](https://developer.android.com/privacy-and-security/security-config#certificates) in its [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config#CustomTrust). Even though starting with Android 7.0 (API level 24) apps no longer trust user-added CAs by default, this configuration overrides that behavior.

Such trust can expose the application to [MITM attacks](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm), as malicious CAs installed by users could intercept secure communications.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Obtain the AndroidManifest.xml (@MASTG-TECH-0117), and check if a `networkSecurityConfig` is set in the `<application>` tag.
3. Inspect the referenced network security config file, and extract all uses of `<certificates src="user" />.

## Observation

The output contains all the `<trust-anchors>` from the Network Security Configuration file along with any defined `<certificates>` entries, if present.

## Evaluation

The test case fails if `<certificates src="user" />` has been defined as part of the `<trust-anchors>` in the Network Security Configuration file.
