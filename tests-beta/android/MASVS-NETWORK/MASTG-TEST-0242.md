---
title: Missing Certificate Pinning in Network Security Configuration
platform: android
id: MASTG-TEST-0242
type: [static]
weakness: MASWE-0047
profiles: [L2]
---

## Overview

Apps can configure [certificate pinning using the Network Security Configuration]("../../../Document/0x05g-Testing-Network-Communication.md#pinning-via-network-security-configuration-api-24"). For each domain, one or multiple digests can be pinned.

The goal of this test is to check if the app does not implement certificate pinning using the NSC. However, note that the app may be using other pinning methods covered in other tests.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Obtain the AndroidManifest.xml (@MASTG-TECH-0117), and check if a `networkSecurityConfig` is set in the `<application>` tag.
3. Inspect the referenced network security config file, and extract all domains from `<domain-config>` which have a pin set (`<pin-set>`).

## Observation

The output should contain a list of domains which enable certificate pinning.

## Evaluation

The test case fails if no `networkSecurityConfig` is set, or any relevant domain does not enable certificate pinning.
