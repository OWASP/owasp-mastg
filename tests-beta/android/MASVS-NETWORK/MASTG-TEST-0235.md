---
title: Android App Configurations Allowing Cleartext Traffic
platform: android
id: MASTG-TEST-0235
type: [static]
weakness: MASWE-0050
profiles: [L1, L2]
---

## Overview

Since Android 9 (API level 28) cleartext HTTP traffic is blocked by default (thanks to the [default Network Security Configuration](../../../Document/0x05g-Testing-Network-Communication.md#default-configurations)) but there are multiple ways in which an application can still send it:

- **AndroidManifest.xml**: Setting the [`android:usesCleartextTraffic`](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic) attribute of the `<application>` tag. Note that this flag is ignored in case the Network Security Configuration is configured.
- **Network Security Configuration**: Setting the [`cleartextTrafficPermitted`](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted) attribute to `true` on `<base-config>` or `<domain-config>` elements.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Obtain the AndroidManifest.xml.
3. Obtain the Network Security Configuration.
4. Read the value of `usesCleartextTraffic` from the AndroidManifest.xml.
5. Read the value of `cleartextTrafficPermitted` from the NSC `<base-config>` element.
6. Read the value of `cleartextTrafficPermitted` from the NSC `<domain-config>` elements.

## Observation

The output contains a list of configurations potentially allowing for cleartext traffic.

## Evaluation

The test case fails if cleartext traffic is permitted. This can happen if any of the following is true:

1. The AndroidManifest sets `usesCleartextTraffic` to `true` and there's no NSC.
2. The NSC sets `cleartextTrafficPermitted` to `true` in the `<base-config>`.
3. The NSC sets `cleartextTrafficPermitted` to `true` in any `<domain-config>`.

**Note:** The test doesn't fail if the AndroidManifest sets `usesCleartextTraffic` to `true` and there's a NSC, even if it only has an empty `<network-security-config>` element. For example:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
</network-security-config>
```
