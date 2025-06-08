---
title: Stack Canaries Not enabled
platform: ios
id: MASTG-TEST-0229
type: [static]
weakness: MASWE-0116
profiles: [L2]
---

## Overview

This test case checks if the main binary or any libraries of the app are compiled without stack canaries and therefore lack [stack smashing protection](../../../Document/0x06i-Testing-Code-Quality-and-Build-Settings.md/#binary-protection-mechanisms), a common mitigation technique against buffer overflow attacks.

This test applies to all binaries and libraries:

- It is especially important for non-memory safe languages like Objective-C or C/C++.
- For pure Swift apps, checking for stack canaries can be usually skipped, as Swift is considered a memory safe by design and conventional parsing techniques cannot detect stack canaries in Swift binaries (see the "canary – exceptions" section of this [blog post](https://sensepost.com/blog/2021/on-ios-binary-protections/)).

To differentiate between Objective-C and Swift binaries, you can inspect the imports and linked libraries. Detecting Objective-C binaries is straightforward, but detecting pure Swift binaries is more challenging because depending on the Swift version and compiler settings, the binary may still contain Objective-C symbols or libraries. See the "identifying objc vs swift" section of this [blog post](https://sensepost.com/blog/2021/on-ios-binary-protections/) for more details.

## Steps

1. Extract the application and identify the main binary (@MASTG-TECH-0054).
2. Identify all shared libraries (@MASTG-TECH-0082).
3. Run @MASTG-TECH-0118 on the main binary and each shared library.
4. If the output contains the symbol `__stack_chk_fail` it indicates stack canaries are enabled.

## Observation

The output should contain a list of symbols of the main binary and each shared library.

## Evaluation

The test case fails any binary or library is not purely Swift but does not contain methods indicating stack canaries like `objc_autorelease` or `objc_retainAutorelease`.

**Note:** Checking for the `__stack_chk_fail` symbol only indicates that stack smashing protection is enabled somewhere in the app. While stack canaries are typically enabled or disabled for the entire binary, there may be corner cases where only parts of the application are protected. For example, if the app developer statically links a library with stack smashing protection enabled, but disables it for the entire application.

If you want to be sure that specific security-critical methods are sufficiently protected, you need to reverse-engineer each of them and manually check for stack smashing protection.

When evaluating this please note that there are potential **expected false positives** for which the test case should be considered as passed. To be certain for these cases, they require manual review of the original source code and the compilation flags used.

The following examples cover some of the false positive cases that might be encountered:

### Use of Memory Safe Languages

The Flutter framework does not use stack canaries because of the way [Dart mitigates buffer overflows](https://docs.flutter.dev/reference/security-false-positives#shared-objects-should-use-stack-canary-values).

### Compiler Optimizations

Sometimes, due to the size of the library and the optimizations applied by the compiler, it might be possible that the library was originally compiled with stack canaries but they were optimized out. For example, this is the case for some [react native apps](https://github.com/facebook/react-native/issues/36870#issuecomment-1714007068). They are built with `-fstack-protector-strong` but when attempting to search for `stack_chk_fail` inside the binary files, it is not found. The React Native developers in this case declare that they won't be adding `-fstack-protector-all` as, in their case, [they consider that doing so will add a performance hit for no effective security gain](https://github.com/facebook/react-native/issues/36870#issuecomment-1714007068).
