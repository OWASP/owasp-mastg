---
title: Obtaining the Code Signature Format Version
platform: ios
---

To extract the code signature format version from a signed binary, you can use @MASTG-TOOL-0114.

The version is obtained by calling `codesign -dv` and identifying the value of `v` in the `CodeDirectory` row:

```bash
$ codesign -dv MASTestApp.app
Executable=/Users/user/MASTestApp.app
Identifier=org.owasp.mastestapp.MASTestApp-iOS
Format=Mach-O universal (armv7 arm64)
CodeDirectory v=20400 size=404674 flags=0x0(none) hashes=12635+7 location=embedded
Signature size=4858
...
```

In this case the version is 20400, since the output contains `v=20400`.
