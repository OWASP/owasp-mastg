---
title: Position Independent Code (PIC) Not Enabled
platform: android
id: MASTG-TEST-0222
deprecated_since: 21
type: [static]
weakness: MASWE-0116
profiles: [L2]
---

## Overview

This test case checks if the [native libraries](../../../Document/0x05i-Testing-Code-Quality-and-Build-Settings.md/#binary-protection-mechanisms) of the app are compiled without enabling [Position Independent Code (PIC)](../../../Document/0x04h-Testing-Code-Quality.md/#position-independent-code), a common mitigation technique against memory corruption attacks.

Since Android 5.0 (API level 21), Android requires [all dynamically linked executables to support PIE](https://source.android.com/docs/security/enhancements/#android-5).

> [Build System Maintainers Guide - Additional Required Arguments](https://android.googlesource.com/platform/ndk/%2B/master/docs/BuildSystemMaintainers.md#additional-required-arguments): Android requires Position-independent executables beginning with API 21. Clang builds PIE executables by default. If invoking the linker directly or not using Clang, use `-pie` when linking.

## Steps

1. Extract the app contents (@MASTG-TECH-0007).
2. Run @MASTG-TECH-0115 on each shared library and grep for "pic" or the corresponding keyword used by the selected tool.

## Observation

The output should list if PIC is enabled or disabled.

## Evaluation

The test case fails if PIC is disabled.
