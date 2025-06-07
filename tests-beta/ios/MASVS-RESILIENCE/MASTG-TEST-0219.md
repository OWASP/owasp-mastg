---
platform: ios
title: Testing for Debugging Symbols
id: MASTG-TEST-0219
type: [static]
weakness: MASWE-0093
profiles: [R]
---

## Overview

This test case checks for [debugging symbols](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0093/) in all binaries contained in the app.

Debugging symbols are added by the [compiler to ease development](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information "Building your app to include debugging information") and allow symbolication of crashes. However, they can also be used to reverse engineer the app and should not be present in a released app. [Symbolication can also be performed](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report "Adding identifiable symbol names to a crash report") with a separate dSYM file.

To manage debugging symbols in Xcode, developers can adjust the following build settings:

- **Generate Debug Symbols**: Xcode adds debugging symbols if the setting [`"Build Settings" > "Apple Clang - Code Generation" > "Generate Debug Symbols"`](https://developer.apple.com/documentation/xcode/build-settings-reference#Generate-Debug-Symbols) is set to `"Yes"`.
- **Debug Information Format**: Found under [`"Build Settings" > "Build Options > "Debug Information Format"`](https://developer.apple.com/documentation/xcode/build-settings-reference#Debug-Information-Format), this setting determines the format of the debug information. Options include:
    - **DWARF**: Embeds debugging information directly into the binary.
    - **DWARF with dSYM File**: Generates a separate dSYM file containing debugging information.

Note that in compiled iOS applications, symbol names may undergo **name mangling** and additional **obfuscation techniques** to further obscure them, making reverse engineering more challenging. While demangling tools can decode standard mangled names (see @MASTG-TECH-0114), they may not effectively reverse custom obfuscation methods.

## Steps

1. Apply @MASTG-TECH-0058 to extract the contents from the IPA file.
2. For all executables and libraries of the app, use @MASTG-TECH-0113 to verify there are no debugging symbols present.

## Observation

The output should contain a list of symbols for each executable and library.

## Evaluation

The test fails if there are symbols marked as debug symbols in the output.

Before releasing an iOS app, verify that the `"Build Settings" > "Apple Clang - Code Generation" > "Generate Debug Symbols"` setting is set to `"No"`. Additionally, utilize tools like the ones used in @MASTG-TECH-0113 to inspect the final binaries for any residual debugging symbols.

For release builds, it's advisable to set `"Build Settings" > "Build Options > "Debug Information Format"` to `"DWARF with dSYM File"` and ensure that the dSYM files are securely stored and not distributed with the app. This approach facilitates post-release crash analysis without exposing debugging symbols in the distributed binary.
