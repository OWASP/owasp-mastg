---
title: Obtaining Compiler-Provided Security Features
platform: android
---

Run @MASTG-TOOL-0129 on the target binary, for example a shared library and grep for the keywords you'd like to check for.

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   false
```
