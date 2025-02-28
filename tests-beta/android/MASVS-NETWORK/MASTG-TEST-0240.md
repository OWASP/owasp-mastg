---
title: Missing Certificate Pinning in Network Security Configuration
platform: android
id: MASTG-TEST-0240
type: [static]
weakness: MASWE-0047
---

## Overview

Apps can configure certificate pinning using the [Network Security Configuration]("../../../Document/0x05g-Testing-Network-Communication.md#certificate-pinning"). For each domain, one or multiple digests can be pinned.

The goal of this test is to check if any certificate pinning exists.

!!! note "Limitations"
    Since there are many different ways to achieve certificate pinning in the code, checking statically if the application performs pinning might not reveal all such locations. To make sure certificates are pinned for all relevant connections, additional dynamic analysis can be performed.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Inspect the AndroidManifest.xml, and check if a `networkSecurityConfig` is set in the `<application>` tag.
3. Inspect the referenced network security config file, and extract all domains which have a pinned certificate.

## Observation

The output should contain a list of domains which enable certificate pinning.

## Evaluation

The test case fails if no `networkSecurityConfig` is set, or any relevant domain does not enable certificate pinning.
