---
title: Position Independent Code (PIC) not enabled
platform: android
id: MASTG-TEST-0222
type: [static]
weakness: MASWE-0116
---

## Overview

This test case checks if the shared libraries of the app are compiled without Position Independent Code (PIC) or [PIE (Position Independent Executable)](https://mas.owasp.org/MASTG/0x04h-Testing-Code-Quality/#position-independent-code), a common mitigation technique against memory corruption attacks.

In general all binaries should be tested, which includes both the main app executable as well as all libraries/dependencies. However, Since Android 7.0 (API level 24), [PIC compilation is enabled by default](https://source.android.com/devices/tech/dalvik/configure) for the main executables. Therefore, on Android we will [focus on native libraries](../../../Document/0x05i-Testing-Code-Quality-and-Build-Settings/#binary-protection-mechanisms).

With Android 5.0 (API level 21), support for [non-PIE enabled native libraries was dropped](https://source.android.com/security/enhancements/enhancements50) and since then, [PIE is enforced by the linker](https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=430). See more details [here](https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md).

## Steps

1. Extract the application.
2. Run @MASTG-TECH-0115 on each shared library and grep for "pic" or the corresponding keyword used by the selected tool.

## Observation

The output should list if PIC is enabled or disabled.

## Evaluation

The test case fails if PIC is disabled.
