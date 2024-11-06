---
title: Position Independent Code (PIC) not enabled
platform: android
id: MASTG-TEST-0x44-1
type: [static]
weakness: MASWE-0116
---

## Overview

This test case checks if the shared libraries of the application have position independent code (PIC) enabled.

## Steps

1. Extract the application.
2. Run @MASTG-TOOL-0028 on each shared library using:

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep "pic"
pic      true
```

## Observation

The output should list if PIC is enabled or disabled.

## Evaluation

The test case fails if PIC is disabled.
