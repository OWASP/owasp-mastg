---
masvs_v1_id:
- MSTG-CODE-3
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: ios
title: Testing for Debugging Symbols
masvs_v1_levels:
- R
profiles: [R]
covered_by: [MASTG-TEST-0219]
status: deprecated
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

To verify the existence of debug symbols you can use objdump from [binutils](https://www.gnu.org/s/binutils/ "Binutils") or [llvm-objdump](https://llvm.org/docs/CommandGuide/llvm-objdump.html "llvm-objdump") to inspect all of the app binaries.

In the following snippet we run objdump over `TargetApp` (the iOS main app executable) to show the typical output of a binary containing debug symbols which are marked with the `d` (debug) flag. Check the [objdump man page](https://www.unix.com/man-page/osx/1/objdump/ "objdump man page") for information about various other symbol flag characters.

```bash
$ objdump --syms TargetApp

0000000100007dc8 l    d  *UND* -[ViewController handleSubmitButton:]
000000010000809c l    d  *UND* -[ViewController touchesBegan:withEvent:]
0000000100008158 l    d  *UND* -[ViewController viewDidLoad]
...
000000010000916c l    d  *UND* _disable_gdb
00000001000091d8 l    d  *UND* _detect_injected_dylds
00000001000092a4 l    d  *UND* _isDebugged
...
```

To prevent the inclusion of debug symbols, set `Strip Debug Symbols During Copy` to `YES` via the XCode project's build settings. Stripping debugging symbols will not only reduce the size of the binary but also increase the difficulty of reverse engineering.

## Dynamic Analysis

Dynamic analysis is not applicable for finding debugging symbols.
