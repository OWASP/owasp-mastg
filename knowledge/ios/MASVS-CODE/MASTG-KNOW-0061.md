---
masvs_category: MASVS-CODE
platform: ios
title: Binary Protection Mechanisms
---

Detecting the presence of [binary protection mechanisms](0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) heavily depend on the language used for developing the application.

Although Xcode enables all binary security features by default, it may be relevant to verify this for old applications or to check for compiler flag misconfigurations. The following features are applicable:

- [**PIE (Position Independent Executable)**](0x04h-Testing-Code-Quality.md#position-independent-code):
    - PIE applies to executable binaries (Mach-O type `MH_EXECUTE`) [source](https://web.archive.org/web/20230328221404/https://opensource.apple.com/source/cctools/cctools-921/include/mach-o/loader.h.auto.html).
    - However it's not applicable for libraries (Mach-O type `MH_DYLIB`).
- [**Memory management**](0x04h-Testing-Code-Quality.md#memory-management):
    - Both pure Objective-C, Swift and hybrid binaries should have ARC (Automatic Reference Counting) enabled.
    - For C/C++ libraries, the developer is responsible for doing proper [manual memory management](0x04h-Testing-Code-Quality.md#manual-memory-management). See ["Memory Corruption Bugs"](0x04h-Testing-Code-Quality.md#memory-corruption-bugs).
- [**Stack Smashing Protection**](0x04h-Testing-Code-Quality.md#stack-smashing-protection): For pure Objective-C binaries, this should always be enabled. Since Swift is designed to be memory safe, if a library is purely written in Swift, and stack canaries weren't enabled, the risk will be minimal.

Learn more:

- [OS X ABI Mach-O File Format Reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
- [On iOS Binary Protections](https://sensepost.com/blog/2021/on-ios-binary-protections/)
- [Security of runtime process in iOS and iPadOS](https://support.apple.com/en-gb/guide/security/sec15bfe098e/web)
- [Mach-O Programming Topics - Position-Independent Code](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/dynamic_code.html)

Tests to detect the presence of these protection mechanisms heavily depend on the language used for developing the application. For example, existing techniques for detecting the presence of stack canaries do not work for pure Swift apps.

## Xcode Project Settings

## Stack Canary protection

Steps for enabling stack canary protection in an iOS application:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Make sure that the "-fstack-protector-all" option is selected in the "Other C Flags" section.
3. Make sure that Position Independent Executables (PIE) support is enabled.

## PIE protection

Steps for building an iOS application as PIE:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Set the iOS Deployment Target to iOS 4.3 or later.
3. Make sure that "Generate Position-Dependent Code" (section "Apple Clang - Code Generation") is set to its default value ("NO").
4. Make sure that "Generate Position-Dependent Executable" (section "Linking") is set to its default value ("NO").

## ARC protection

ARC is automatically enabled for Swift apps by the `swiftc` compiler. However, for Objective-C apps you'll have ensure that it's enabled by following these steps:

1. In Xcode, select your target in the "Targets" section, then click the "Build Settings" tab to view the target's settings.
2. Make sure that "Objective-C Automatic Reference Counting" is set to its default value ("YES").

See the [Technical Q&A QA1788 Building a Position Independent Executable](https://developer.apple.com/library/mac/qa/qa1788/_index.html "Technical Q&A QA1788 Building a Position Independent Executable").
