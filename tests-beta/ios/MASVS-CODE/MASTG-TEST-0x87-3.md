---
title: Automatic Reference Counting (ARC) not enabled
platform: ios
id: MASTG-TEST-0x87-3
type: [static]
weakness: MASWE-0116
---

## Overview

[ARC (Automatic Reference Counting)](../../../Document/0x04h-Testing-Code-Quality/#automatic-reference-counting) is a memory management feature of the compiler for the Objective-C and Swift code.

The main binary and all libraries should enable ARC if they contain Objective-C or Swift code.
    - For libraries containing Objective-C code, it can be enabled via the `-fobjc-arc` of clang.
    - For libraries written purely in Swift, ARC is enabled by default.

For libraries written purely in C/C++, ARC is not available.

Once ARC is enabled, symbols such as `objc_autorelease` or `objc_retainAutorelease` will be present in the binaries.

This test case checks if ARC is enabled.

## Steps

1. Extract the application.
2. Run @MASTG-TECH-0113 on the main binary (`App.app/YourApp`) and each shared library (e.g., stored in the Frameworks folder)
3. If the output contains symbols indicating the usage of Objective-C (e.g., `_objc_msgSend`) or symbols indicating the usage of Swift (e.g., `_swift_allocObject`), check if the symbols `objc_autorelease` or `objc_retainAutorelease` exist in the main binary and each shared library.

!!! note Completeness of the check
    Checking for these symbols only indicates that ARC is enabled somewhere in the app. Whilst typically ARC will be enabled or disabled for the whole binary, there can be corner cases, where only parts of the application or libraries are protected. E.g., when the app developer statically links a library that has ARC enabled, but disables it for the whole application.
    If you want to be sure specific security critical methods are protected sufficiently, you need to reverse engineer each, and check for ARC manually.

## Observation

The output should contain a list of symbols of the main binary and each shared library.

## Evaluation

The test case fails if any binary or library is not purely C/C++ and does not contain methods indicating ARC is present like `objc_autorelease` or `objc_retainAutorelease`.
