---
masvs_v1_id:
- MSTG-RESILIENCE-6
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: android
title: Testing Runtime Integrity Checks
masvs_v1_levels:
- R
profiles: [R]
---

## Effectiveness Assessment

Make sure that all file-based detection of reverse engineering tools is disabled. Then, inject code by using Xposed, Frida, and Substrate, and attempt to install native hooks and Java method hooks. The app should detect the "hostile" code in its memory and respond accordingly.

Work on bypassing the checks with the following techniques:

1. Patch the integrity checks. Disable the unwanted behavior by overwriting the respective bytecode or native code with NOP instructions.
2. Use Frida or Xposed to hook the APIs used for detection and return fake values.
