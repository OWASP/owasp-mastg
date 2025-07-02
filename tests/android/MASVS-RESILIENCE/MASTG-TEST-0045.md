---
masvs_v1_id:
- MSTG-RESILIENCE-1
masvs_v2_id:
- MASVS-RESILIENCE-1
platform: android
title: Testing Root Detection
masvs_v1_levels:
- R
profiles: [R]
---

## Bypassing Root Detection

Run execution traces with jdb, [DDMS](https://developer.android.com/studio/profile/monitor "DDMS"), `strace`, and/or kernel modules to find out what the app is doing. You'll usually see all kinds of suspect interactions with the operating system, such as opening `su` for reading and obtaining a list of processes. These interactions are surefire signs of root detection. Identify and deactivate the root detection mechanisms, one at a time. If you're performing a black box resilience assessment, disabling the root detection mechanisms is your first step.

To bypass these checks, you can use several techniques, most of which were introduced in the "Reverse Engineering and Tampering" chapter:

- Renaming binaries. For example, in some cases simply renaming the `su` binary is enough to defeat root detection (try not to break your environment though!).
- Unmounting `/proc` to prevent reading of process lists. Sometimes, the unavailability of `/proc` is enough to bypass such checks.
- Using Frida or Xposed to hook APIs on the Java and native layers. This hides files and processes, hides the contents of files, and returns all kinds of bogus values that the app requests.
- Hooking low-level APIs by using kernel modules.
- Patching the app to remove the checks.

## Effectiveness Assessment

Check for root detection mechanisms, including the following criteria:

- Multiple detection methods are scattered throughout the app (as opposed to putting everything into a single method).
- The root detection mechanisms operate on multiple API layers (Java APIs, native library functions, assembler/system calls).
- The mechanisms are somehow original (they're not copied and pasted from StackOverflow or other sources).

Develop bypass methods for the root detection mechanisms and answer the following questions:

- Can the mechanisms be easily bypassed with standard tools, such as @MASTG-TOOL-0142?
- Is static/dynamic analysis necessary to handle the root detection?
- Do you need to write custom code?
- How long did successfully bypassing the mechanisms take?
- What is your assessment of the difficulty of bypassing the mechanisms?

If root detection is missing or too easily bypassed, make suggestions in line with the effectiveness criteria listed above. These suggestions may include more detection mechanisms and better integration of existing mechanisms with other defenses.
