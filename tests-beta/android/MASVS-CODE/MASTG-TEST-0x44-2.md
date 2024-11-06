---
title: Stack Canaries not enabled
platform: android
id: MASTG-TEST-0x44-2
type: [static]
weakness: MASWE-0116
---

## Overview

This test case checks if the shared libraries of the application are compiled without stack canaries.

## Steps

1. Extract the application.
2. Run @MASTG-TOOL-0028 on each shared library using:

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep "canary"
canary   false
```

## Observation

The output should list if stack canaries are enabled or disabled.

## Evaluation

The test case fails if stack canaries are disabled.
