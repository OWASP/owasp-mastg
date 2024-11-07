---
title: Stack Canaries not enabled
platform: ios
id: MASTG-TEST-0x87-2
type: [static]
weakness: MASWE-0116
---

## Overview

This test case checks if the main binary or any libraries of the app are compiled without stack canaries and therefore lack [stack smashing protection](../../../Document/0x06i-Testing-Code-Quality-and-Build-Settings/#binary-protection-mechanisms), a common mitigation technique against buffer overflow attacks.

This test applies to all binaries and libraries, but is especially important for non-memory safe languages like Objective-C or C/C++.

## Steps

1. Extract the application.
2. Run @MASTG-TECH-0113 on the main binary (`App.app/YourApp`) and each shared library (e.g., stored in the Frameworks folder)
3. If the output contains the symbol `__stack_chk_fail` it indicates stack canaries are enabled.

!!! note Completeness of the check
    Checking for the symbol `__stack_chk_fail` only indicates that stack smashing protection is enabled somewhere in the app. Whilst stack canaries are typically enabled or disabled for the whole binary, there can be corner cases, where only parts of the application are protected. E.g., when the app developer statically links a library with enables stack smashing protection, but disables it for the whole application.
    If you want to be sure specific security critical methods are protected sufficiently, you need to reverse engineer each, and check for stack smashing protection manually.

## Observation

The output should contain a list of symbols of the main binary and each shared library.

## Evaluation

The test case fails any binary or library is not purely Swift but does not contain methods indicating stack canaries like `objc_autorelease` or `objc_retainAutorelease`.
