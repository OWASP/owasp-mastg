---
masvs_v1_id:
- MSTG-RESILIENCE-2
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: ios
title: Testing Anti-Debugging Detection
masvs_v1_levels:
- R
profiles: [R]
---

## Overview

In order to test for anti-debugging detection you can try to attach a debugger to the app and see what happens.

The app should respond in some way. For example by:

- Alerting the user and asking for accepting liability.
- Preventing execution by gracefully terminating.
- Securely wiping any sensitive data stored on the device.
- Reporting to a backend server, e.g, for fraud detection.

Try to hook or reverse engineer the app using the methods from section ["Anti-Debugging Detection"](../../../Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#anti-debugging).

Next, work on bypassing the detection and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the detection code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?
