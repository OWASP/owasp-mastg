---
title: Runtime Use Of Root Detection
platform: android
id: MASTG-TEST-0246
type: [dynamic]
weakness: MASWE-0097
best-practices: []
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0245.

## Steps

1. **Monitor Application Behaviour:**
   - Use tools like strace or similar utilities to trace how the app checks for root access. Look for interactions with the system, such as attempts to open su, check running processes, or read root-specific files. This analysis helps uncover how the app performs root detection and may reveal potential weaknesses.

2. **Bypassing Root Detection Mechanisms**
   - Run a dynamic analysis tool such as @MASTG-TOOL-0038 to attempt automated root detection bypass. Use commands to manipulate root checks and observe whether the app still correctly detects root access or if its security mechanisms can be bypassed.

## Observation

The output should include any observed instances of common root detection checks performed by the app and the results of the automated root detection bypass attempts.

## Evaluation

The test fails if no root detection mechanisms are identified, indicating that the app does not attempt to detect root access. However, this test is not exhaustive, as it relies on predefined bypass techniques that may not cover all possible root detection methods or may be outdated. Additionally, some applications may use more advanced detection mechanisms that automated tools cannot easily identify, requiring manual reverse engineering and deobfuscation to fully assess their effectiveness.
