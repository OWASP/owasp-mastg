---
title: Stack Canaries not enabled
platform: android
id: MASTG-TEST-0223
type: [static]
weakness: MASWE-0116
---

## Overview

This test case checks if the shared libraries of the app are compiled without stack canaries and therefore lacking [stack smashing protection](../../../Document/0x04h-Testing-Code-Quality/#stack-smashing-protection), a common mitigation technique against buffer overflow attacks.

In general all binaries should be tested, which includes both the main app executable as well as all libraries/dependencies. However, Android apps get compiled to Dalvik bytecode which is considered memory safe (at least for mitigating buffer overflows). Other frameworks such as Flutter will not compile using stack canaries because of the way their language, in this case Dart, mitigates buffer overflows. Therefore, on Android we will [focus on native libraries](../../../Document/0x05i-Testing-Code-Quality-and-Build-Settings/#binary-protection-mechanisms) since the main executables are considered safe.

Stack canaries must be enabled for Android native libraries but it might be difficult to fully determine it.

- NDK libraries should have it enabled since the compiler does it by default.
- Other custom C/C++ libraries might not have it enabled.

## Steps

1. Extract the application.
2. Run @MASTG-TECH-0115 on each shared library and grep for "canary" or the corresponding keyword used by the selected tool.

## Observation

The output should show if stack canaries are enabled or disabled.

## Evaluation

The test case fails if stack canaries are disabled.
