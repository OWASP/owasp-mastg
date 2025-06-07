---
masvs_v1_id:
- MSTG-RESILIENCE-1
masvs_v2_id:
- MASVS-RESILIENCE-1
platform: ios
title: Testing Jailbreak Detection
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0240, MASTG-TEST-0241]
deprecation_note: New version available in MASTG V2
---

## Overview

To test for jailbreak detection install the app on a jailbroken device.

**Launch the app and see what happens:**

If it implements jailbreak detection, you might notice one of the following things:

- The app crashes and closes immediately, without any notification.
- A pop-up window indicates that the app won't run on a jailbroken device.

Note that crashes might be an indicator of jailbreak detection but the app may be crashing for any other reasons, e.g. it may have a bug. We recommend to test the app on non-jailbroken device first, especially when you're testing preproduction versions.

**Launch the app and try to bypass Jailbreak Detection using an automated tool:**

If it implements jailbreak detection, you might be able to see indicators of that in the output of the tool. See section ["Automated Jailbreak Detection Bypass"](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#automated-jailbreak-detection-bypass).

**Reverse Engineer the app:**

The app might be using techniques that are not implemented in the automated tools that you've used. If that's the case you must reverse engineer the app to find proofs. See section ["Manual Jailbreak Detection Bypass"](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#manual-jailbreak-detection-bypass).
