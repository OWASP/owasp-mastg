---
masvs_v1_id:
- MSTG-STORAGE-3
masvs_v2_id:
- MASVS-STORAGE-2
platform: ios
title: Checking Logs for Sensitive Data
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

Use the following keywords to check the app's source code for predefined and custom logging statements:

- For predefined and built-in functions:
    - NSLog
    - NSAssert
    - NSCAssert
    - fprintf
- For custom functions:
    - Logging
    - Logfile

A generalized approach to this issue is to use a define to enable `NSLog` statements for development and debugging, then disable them before shipping the software. You can do this by adding the following code to the appropriate PREFIX_HEADER (\*.pch) file:

```objectivec
#ifdef DEBUG
#   define NSLog (...) NSLog(__VA_ARGS__)
#else
#   define NSLog (...)
#endif
```

## Dynamic Analysis

See @MASTG-TECH-0060 and once you're set up, navigate to a screen that displays input fields that take sensitive user information.

After starting one of the methods, fill in the input fields. If sensitive data is displayed in the output, the app fails this test.
