---
masvs_v1_id:
- MSTG-RESILIENCE-3
- MSTG-RESILIENCE-11
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: ios
title: Testing File Integrity Checks
masvs_v1_levels:
- R
profiles: [R]
---

## Overview

**Application Source Code Integrity Checks:**

Run the app on the device in an unmodified state and make sure that everything works. Then apply some patches to the executable (e.g. see @MASTG-TECH-0090), re-sign the app (@MASTG-TECH-0092), and run it.

The app should respond in some way. For example by:

- Alerting the user and asking for accepting liability.
- Preventing execution by gracefully terminating.
- Securely wiping any sensitive data stored on the device.
- Reporting to a backend server, e.g, for fraud detection.

Work on bypassing the defenses and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the detection code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

**File Storage Integrity Checks:**

Go to the app data directories as indicated in @MASTG-TECH-0059 and modify some files.

Next, work on bypassing the defenses and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by changing the contents of a file or a key-value pair)?
- How difficult is obtaining the HMAC key or the asymmetric private key?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?
