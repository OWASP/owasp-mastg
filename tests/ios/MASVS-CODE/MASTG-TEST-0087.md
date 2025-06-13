---
masvs_v1_id:
- MSTG-CODE-9
masvs_v2_id:
- MASVS-CODE-4
platform: ios
title: Make Sure That Free Security Features Are Activated
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0228, MASTG-TEST-0229, MASTG-TEST-0230]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

You can use radare2 to check the binary security features.

Let's use the [Damn Vulnerable iOS App DVIA v1](https://github.com/prateek147/DVIA/) as an example. Open its main binary with radare2:

```bash
r2 DamnVulnerableIOSApp
```

And run the following commands:

```bash
[0x1000180c8]> i~pic,canary
canary   true
pic      true
```

```bash
[0x1000180c8]> is~release,retain
124  0x002951e0 0x1000891e0 LOCAL  FUNC 0        imp.dispatch_release
149  0x00294e80 0x100088e80 LOCAL  FUNC 0        imp.objc_autorelease
150  0x00294e8c 0x100088e8c LOCAL  FUNC 0        imp.objc_autoreleasePoolPop
151  0x00294e98 0x100088e98 LOCAL  FUNC 0        imp.objc_autoreleasePoolPush
152  0x00294ea4 0x100088ea4 LOCAL  FUNC 0        imp.objc_autoreleaseReturnValue
165  0x00294f40 0x100088f40 LOCAL  FUNC 0        imp.objc_release
167  0x00294f58 0x100088f58 LOCAL  FUNC 0        imp.objc_retainAutorelease
168  0x00294f64 0x100088f64 LOCAL  FUNC 0        imp.objc_retainAutoreleaseReturnValue
169  0x00294f70 0x100088f70 LOCAL  FUNC 0        imp.objc_retainAutoreleasedReturnValue
```

All the features are enabled in these examples:

- PIE (Position Independent Executable): indicated by the flag `pic true`.
    - Applies to all apps independently of the language used.
    - Applies only to the main executable (`MH_EXECUTE`), not to dynamic libraries (`MH_DYLIB`).

- Stack Canary: indicated by the flag `canary true`.
    - Applies to apps containing Objective-C code.
    - Not necessarily required for pure Swift apps (Swift is memory safe by design).
    - Especially important for apps containing C/C++ code, as they provide direct access to memory and pointers, making them more vulnerable to buffer overflows.

- ARC (Automatic Reference Counting): indicated by symbols such as `objc_autorelease` or `objc_retainAutorelease`.
    - Important for binaries containing Objective-C code.
    - For binaries written purely in Swift, ARC is enabled by default.
    - ARC is not relevant for binaries written purely in C/C++, as it's a memory management feature specific to Objective-C and Swift.

## Dynamic Analysis

These checks can be performed dynamically using @MASTG-TOOL-0038. Here's one example:

```bash
com.yourcompany.PPClient on (iPhone: 13.2.3) [usb] # ios info binary
Name                  Type     Encrypted    PIE    ARC    Canary    Stack Exec    RootSafe
--------------------  -------  -----------  -----  -----  --------  ------------  ----------
PayPal                execute  True         True   True   True      False         False
CardinalMobile        dylib    False        False  True   True      False         False
FraudForce            dylib    False        False  True   True      False         False
...
```
