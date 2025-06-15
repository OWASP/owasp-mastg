---
title: Network Security Configuration Allowing Trust in User-Provided CAs
platform: android
id: MASTG-TEST-0234-5
type: [static]
weakness: MASWE-0052
---

## Overview

Even though starting on Android 7.0 (API level 24) apps no longer trust user-added CAs by default, developers can override this behaviour by explicitly including `<certificates src="user"/>` in their network security configuration. Such trust can expose the application to man-in-the-middle (MITM) attacks, as malicious CAs installed by users could intercept secure communications.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Obtain the AndroidManifest.xml (@MASTG-TECH-0117), and check if a `networkSecurityConfig` is set in the `<application>` tag.
3. Inspect the referenced network security config file, and extract all uses of `<certificates src="user" />.

## Observation

The output contains all the `<trust-anchors>` from the Network Security Configuration file along with any defined `<certificates>` entries, if present.

## Evaluation

The test case fails if `<certificates src="user" />` has been defined as part of the `<trust-anchors>` in the Network Security Configuration file.
