---
title: Debuggable Flag Not Disabled in the AndroidManifest
platform: android
id: MASTG-TEST-0x39-1
type: [static]
available_since: 24
weakness: MASWE-0104
---

## Overview

Applications need to be properly signed to safeguard their integrity and protect them from tampering. Android has evolved its signing schemes over time to enhance security, with newer versions offering more robust mechanisms. Check [APK Signing Schemes](../../../Document/0x05a-Platform-Overview.md#signing-process) for more details.

This test checks if the insecure v1 signature scheme is enabled for applications targetting Android 7.0 (API level 24) and above.

## Steps

1. View the `minSDK` version in the AndroidManifest.xml, e.g., via @MASTG-TOOL-0121, and make sure the app targets Android 7.0 (API level 24) and above.
2. List all used signature schemes using @MASTG-TOOL-0122.

## Observation

The output should contain the used signature schemes.

## Evaluation

The test case fails if the app targets Android 7.0 (API level 24) and above, and the v1 signature scheme is enabled.
