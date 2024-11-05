---
title: Cleartext traffic permitted
platform: android
id: MASTG-TEST-0x19-3
type: [static]
weakness: MASWE-0050
---

## Overview

Since Android 9 (API level 28) cleartext HTTP traffic is blocked by default (thanks to the [default Network Security Configuration](../../../Document/0x05g-Testing-Network-Communication.md#default-configurations)) but there are multiple ways in which an application can still send it:

- Setting the [`android:usesCleartextTraffic`](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic "Android documentation - usesCleartextTraffic flag") attribute of the `<application>` tag in the AndroidManifest.xml file. Note that this flag is ignored in case the Network Security Configuration is configured.
- Configuring the [Network Security Configuration to enable cleartext traffic](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted) by setting the `cleartextTrafficPermitted` attribute to true on `<domain-config>` elements.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Verify `usesCleartextTraffic` is not set to `true` in the AndroidManifest.xml
3. Inspect the AndroidManifest.xml, and check if a `networkSecurityConfig` is set in the `<application>` tag. If yes, inspect the referenced file, and make sure that `cleartextTrafficPermitted` is not set to `true` globally in the `<base-config>` element, or for specific domains in their `<domain-config>` elements.

## Observation

The output contains a list of configurations allowing for cleartext traffic.

## Evaluation

The test case fails if any cleartext traffic is permitted.
