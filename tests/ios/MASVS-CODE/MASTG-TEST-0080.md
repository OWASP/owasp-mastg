---
masvs_v1_id:
- MSTG-ARCH-9
masvs_v2_id:
- MASVS-CODE-2
platform: ios
title: Testing Enforced Updating
masvs_v1_levels:
- L2
profiles: [L2]
---

## Overview

## Static Analysis

First see whether there is an update mechanism at all: if it is not yet present, it might mean that users cannot be forced to update.
If the mechanism is present, see whether it enforces "always latest" and whether that is indeed in line with the business strategy. Otherwise check if the mechanism is supporting to update to a given version.
Make sure that every entry of the application goes through the updating mechanism in order to make sure that the update-mechanism cannot be bypassed.

## Dynamic analysis

In order to test for proper updating: try downloading an older version of the application with a security vulnerability, either by a release from the developers or by using a third party app-store.
Next, verify whether or not you can continue to use the application without updating it. If an update prompt is given, verify if you can still use the application by canceling the prompt or otherwise circumventing it through normal application usage. This includes validating whether the backend will stop calls to vulnerable backends and/or whether the vulnerable app-version itself is blocked by the backend.
Lastly, try modifying the version number of an app while intercepting its traffic using a [Machine-in-the-Middle (MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) proxy, and observe how the backend responds (including whether the change is recorded, for example).
