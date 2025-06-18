---
title: Outdated Android Version Allowing Trust in User-Provided CAs
platform: android
id: MASTG-TEST-0234-4
type: [static]
deprecated_since: 24
weakness: MASWE-0052
---

## Overview

This test evaluates whether an Android app can be installed to devices running API level 23 or lower, thereby relying on the default Network Security Configuration that trusts both system and user-installed Certificate Authorities (CAs). Such trust can expose the application to [MITM attacks](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm), as malicious CAs installed by users could intercept secure communications.

## Steps

1. Obtain the AndroidManifest.xml (@MASTG-TECH-0117).
2. Read the value of the `minSdkVersion` attribute from the `<uses-sdk>` element.

## Observation

The output contains the value of `minSdkVersion`.

## Evaluation

The test case fails if `minSdkVersion` is less than 24.
