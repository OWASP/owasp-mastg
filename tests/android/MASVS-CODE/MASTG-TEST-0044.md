---
masvs_v1_id:
- MSTG-CODE-9
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: Make Sure That Free Security Features Are Activated
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0222, MASTG-TEST-0223]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

Test the app native libraries to determine if they have the PIE and stack smashing protections enabled.

You can use @MASTG-TOOL-0129 to get the binary information. We'll use the @MASTG-APP-0015 v1.0 APK as an example.

All native libraries must have `canary` and `pic` both set to `true`.

That's the case for `libnative-lib.so`:

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   true
pic      true
```

But not for `libtool-checker.so`:

```sh
rabin2 -I lib/x86_64/libtool-checker.so | grep -E "canary|pic"
canary   false
pic      true
```

In this example, `libtool-checker.so` must be recompiled with stack smashing protection support.
