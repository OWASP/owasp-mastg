---
title: Position Independent Code (PIC) not Enabled
platform: ios
id: MASTG-TEST-0228
type: [static]
weakness: MASWE-0116
profiles: [L2]
---

## Overview

[PIE (Position Independent Executables)](../../../Document/0x04h-Testing-Code-Quality.md/#position-independent-code) are designed to enhance security by allowing executables to be loaded at random memory addresses, mitigating certain types of attacks.

In the context Mach-O file format of iOS applications:

- PIE is applicable to executables with the `MH_EXECUTE` file type, which essentially means the main app binary (e.g. `YourApp.app/YourApp`).
- Shared libraries with the `MH_DYLIB` file type (dylibs and frameworks) are inherently position-independent and do not utilize the `MH_PIE` flag.

This test case checks if the main executable is compiled with PIE.

## Steps

1. Extract the application and identify the main binary (@MASTG-TECH-0054).
2. Run @MASTG-TECH-0118 on the main binary and grep for "pic" or the corresponding keyword used by the selected tool.

## Observation

The output should list if PIC is enabled or disabled.

## Evaluation

The test case fails if PIC is disabled.
