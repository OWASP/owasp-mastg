---
title: Expired Certificate Pins in the Network Security Configuration 
platform: android
id: MASTG-TEST-0243
type: [static]
weakness: MASWE-0047
profiles: [L2]
---

## Overview

Apps can configure expiration dates for pinned certificates in the [Network Security Configuration (NSC)]("../../../Document/0x05g-Testing-Network-Communication.md#certificate-pinning") by using the `expiration` attribute. When a pin expires, the app no longer enforces certificate pinning and instead relies on its configured trust anchors. This means the connection will still succeed if the server presents a valid certificate from a trusted CA (such as a system CA or a custom CA defined in the app's configuration). However, if no trusted certificate is available, the connection will fail.

If developers assume pinning is still in effect but don't realize it has expired, the app may start trusting CAs it was never intended to.

> Example: A financial app previously pinned to its own private CA but, after expiration, starts trusting publicly trusted CAs, increasing the risk of compromise if a CA is breached.

The goal of this test is to check if any expiration date is in the past.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Inspect the AndroidManifest.xml, and check if a `networkSecurityConfig` is set in the `<application>` tag. If yes, inspect the referenced file, and extract the expiration dates for every domain.

## Observation

The output should contain a list of expiration dates for pinned certificates.

## Evaluation

The test case fails if any expiration date is in the past.
