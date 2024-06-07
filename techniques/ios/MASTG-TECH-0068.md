---
title: Disassembling Native Code
platform: ios
---

Because Objective-C and Swift are fundamentally different, the programming language in which the app is written affects the possibilities for reverse engineering it. For example, Objective-C allows method invocations to be changed at runtime. This makes hooking into other app functions (a technique heavily used by [Cycript](http://www.cycript.org/ "Cycript") and other reverse engineering tools) easy. This "method swizzling" is not implemented the same way in Swift, and the difference makes the technique harder to execute with Swift than with Objective-C.

On iOS, all the application code (both Swift and Objective-C) is compiled to machine code (e.g. ARM). Thus, to analyze iOS applications a disassembler is needed.

If you want to disassemble an application from the App Store, remove the Fairplay DRM first. Section "[Acquiring the App Binary](0x06b-iOS-Security-Testing.md#acquiring-the-app-binary "Acquiring the App Binary")" in the chapter "iOS Basic Security Testing" explains how.

In this section the term "app binary" refers to the Macho-O file in the application bundle which contains the compiled code, and should not be confused with the application bundle - the IPA file. See section "[Exploring the App Package](0x06b-iOS-Security-Testing.md#exploring-the-app-package "Exploring the App Package")" in chapter "Basic iOS Security Testing" for more details on the composition of IPA files.

## Disassembling With IDA Pro

If you have a license for IDA Pro, you can analyze the app binary using IDA Pro as well.

> The free version of IDA unfortunately does not support the ARM processor type.

To get started, simply open the app binary in IDA Pro.

<img src="Images/Chapters/0x06c/ida_macho_import.png" width="100%" />

Upon opening the file, IDA Pro will perform auto-analysis, which can take a while depending on the size of the binary. Once the auto-analysis is completed you can browse the disassembly in the **IDA View** (Disassembly) window and explore functions in the **Functions** window, both shown in the screenshot below.

<img src="Images/Chapters/0x06c/ida_main_window.png" width="100%" />

A regular IDA Pro license does not include a decompiler by default and requires an additional license for the Hex-Rays decompiler, which is expensive. In contrast, Ghidra comes with a very capable free builtin decompiler, making it a compelling alternative to use for reverse engineering.

If you have a regular IDA Pro license and do not want to buy the Hex-Rays decompiler, you can use Ghidra's decompiler by installing the [GhIDA plugin](https://github.com/Cisco-Talos/GhIDA/) for IDA Pro.

The majority of this chapter applies to applications written in Objective-C or having bridged types, which are types compatible with both Swift and Objective-C. The Swift compatibility of most tools that work well with Objective-C is being improved.
