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
---

## Overview

## Static Analysis

You can use [otool](../../Document/0x08a-Testing-Tools.md#otool) to check the binary security features described above. All the features are enabled in these examples.

- PIE:

    ```bash
    $ unzip DamnVulnerableiOSApp.ipa
    $ cd Payload/DamnVulnerableIOSApp.app
    $ otool -hv DamnVulnerableIOSApp
    DamnVulnerableIOSApp (architecture armv7):
    Mach header
    magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
    MH_MAGIC ARM V7 0x00 EXECUTE 38 4292 NOUNDEFS DYLDLINK TWOLEVEL
    WEAK_DEFINES BINDS_TO_WEAK PIE
    DamnVulnerableIOSApp (architecture arm64):
    Mach header
    magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
    MH_MAGIC_64 ARM64 ALL 0x00 EXECUTE 38 4856 NOUNDEFS DYLDLINK TWOLEVEL
    WEAK_DEFINES BINDS_TO_WEAK PIE
    ```

    The output shows that the Mach-O flag for `PIE` is set. This check is applicable to all - Objective-C, Swift and hybrid apps but only to the main executable.

- Stack canary:

    ```bash
    $ otool -Iv DamnVulnerableIOSApp | grep stack
    0x0046040c 83177 ___stack_chk_fail
    0x0046100c 83521 _sigaltstack
    0x004fc010 83178 ___stack_chk_guard
    0x004fe5c8 83177 ___stack_chk_fail
    0x004fe8c8 83521 _sigaltstack
    0x00000001004b3fd8 83077 ___stack_chk_fail
    0x00000001004b4890 83414 _sigaltstack
    0x0000000100590cf0 83078 ___stack_chk_guard
    0x00000001005937f8 83077 ___stack_chk_fail
    0x0000000100593dc8 83414 _sigaltstack
    ```

    In the above output, the presence of `__stack_chk_fail` indicates that stack canaries are being used. This check is applicable to pure Objective-C and hybrid apps, but not necessarily to pure Swift apps (i.e. it is OK if it's shown as disabled because Swift is memory safe by design).

- ARC:

    ```bash
    $ otool -Iv DamnVulnerableIOSApp | grep release
    0x0045b7dc 83156 ___cxa_guard_release
    0x0045fd5c 83414 _objc_autorelease
    0x0045fd6c 83415 _objc_autoreleasePoolPop
    0x0045fd7c 83416 _objc_autoreleasePoolPush
    0x0045fd8c 83417 _objc_autoreleaseReturnValue
    0x0045ff0c 83441 _objc_release
    [SNIP]
    ```

    This check is applicable to all cases, including pure Swift apps where it's automatically enabled.

## Dynamic Analysis

These checks can be performed dynamically using [objection](../../Document/0x08a-Testing-Tools.md#objection). Here's one example:

```bash
com.yourcompany.PPClient on (iPhone: 13.2.3) [usb] # ios info binary
Name                  Type     Encrypted    PIE    ARC    Canary    Stack Exec    RootSafe
