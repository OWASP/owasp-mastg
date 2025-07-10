---
masvs_v1_id:
- MSTG-RESILIENCE-4
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: ios
title: Testing Reverse Engineering Tools Detection
masvs_v1_levels:
- R
profiles: [R]
---

## Overview

Launch the app with various reverse engineering tools and frameworks installed on your test device, such as @MASTG-TOOL-0031, @MASTG-TOOL-0139, or @MASTG-TOOL-0066.

The app should respond in some way to the presence of those tools. For example by:

- Alerting the user and asking for accepting liability.
- Preventing execution by gracefully terminating.
- Securely wiping any sensitive data stored on the device.
- Reporting to a backend server, e.g, for fraud detection.

Next, work on bypassing the detection of the reverse engineering tools and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the detection code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?
