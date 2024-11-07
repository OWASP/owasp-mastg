---
title: Position Independent Code (PIC) not enabled
platform: ios
id: MASTG-TEST-0x87-1
type: [static]
weakness: MASWE-0116
---

## Overview

[PIE (Position Independent Executables)](../../../Document/0x04h-Testing-Code-Quality/#position-independent-code) are designed to enhance security by allowing executables to be loaded at random memory addresses, mitigating certain types of attacks. In the context Mach-O file format of iOS applications, PIE is applicable to executables with the `MH_EXECUTE` file type, which essentially means the main binary of the application.

Conversely, shared libraries with the `MH_DYLIB` file type (dylibs and frameworks) are inherently position-independent and do not utilize the `MH_PIE` flag.

This test case checks if the main executable is compiled without PIE.

## Steps

1. Extract the application.
2. Run @MASTG-TECH-0115 on the main binary (`App.app/YourApp`) and grep for "pic" or the corresponding keyword used by the selected tool.

## Observation

The output should list if PIC is enabled or disabled.

## Evaluation

The test case fails if PIC is disabled.
