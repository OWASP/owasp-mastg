---
title: Automatic Reference Counting (ARC) not enabled
platform: ios
id: MASTG-TEST-0230
type: [static]
weakness: MASWE-0116
profiles: [L2]
---

## Overview

This test case checks if [ARC (Automatic Reference Counting)](../../../Document/0x04h-Testing-Code-Quality.md/#automatic-reference-counting) is enabled in iOS apps. ARC is a compiler feature in Objective-C and Swift that automates memory management, reducing the likelihood of memory leaks and other related issues. Enabling ARC is crucial for maintaining the security and stability of iOS applications.

- **Objective-C Code:** ARC can be enabled by compiling with the `-fobjc-arc` flag in Clang.
- **Swift Code:** ARC is enabled by default.
- **C/C++ Code:** ARC is not applicable, as it pertains specifically to Objective-C and Swift.

When ARC is enabled, binaries will include symbols such as `objc_autorelease` or `objc_retainAutorelease`.

## Steps

1. Extract the application and identify the main binary (@MASTG-TECH-0054).
2. Identify all shared libraries (@MASTG-TECH-0082).
3. Run @MASTG-TECH-0118 on the main binary and each shared library looking for ARC symbols like `objc_autorelease` or `objc_retainAutorelease`.

## Observation

The output should contain a list of symbols of the main binary and each shared library.

## Evaluation

The test fails if any binary or library containing Objective-C or Swift code is missing ARC-related symbols. The presence of symbols such as `_objc_msgSend` (Objective-C) or `_swift_allocObject` (Swift) without corresponding ARC symbols indicates that ARC may not be enabled.

**Note:** Checking for these symbols only indicates that ARC is enabled somewhere in the app. While ARC is typically enabled or disabled for the entire binary, there can be corner cases where only parts of the application or libraries are protected. For example, if the app developer statically links a library that has ARC enabled, but disables it for the entire application.

If you want to be sure that specific security-critical methods are adequately protected, you need to reverse-engineer each of them and manually check for ARC, or request the source code from the developer.
