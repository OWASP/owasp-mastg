---
platform: ios
title: Testing for Debugging Symbols
id: MASTG-TEST-0x83
type: [static]
weakness: MASWE-0093
---

## Overview

This test case checks for [debugging symbols](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0093/) in all binaries
contained in the app.

Debugging symbols are added by the [compiler to ease
development](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information
"Building your app to include debugging information") and allow symbolication of crashes. However, they can also be used
to reverse engineer the app and should not be present in a released app. [Symbolication can also be
performed](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report "Adding
identifiable symbol names to a crash report") with a separate dSYM file.

Xcode adds debugging symbols if the setting "Generate Debug Symbols" under "Build Settings" is set to "Yes". It
generates a separate dSYM file if "Debug Information Format" under "Build Settings" is set to "DWARF with dSYM File" or
embeds DWARF information when it is set to "DWARF".

Some of the symbol names can be mangled (see @MASTG-TECH-0114) or even intentionally obfuscated.

!!! warning Limitation
    You can find some debugging symbols unless the developer has set "Generate Debug Symbols" under
    "Apple Clang - Code Generation" in Xcode to "No".

## Steps

1. Apply @MASTG-TECH-0058 to get a hold of the app's contents.
2. For all executables and libraries of the app, use @MASTG-TECH-0113 to verify there are no debugging symbols present.

## Observation

The output should contain a list of symbols for each executable and library.

## Evaluation

The test fails if there are symbols marked as debug symbols in the output.
