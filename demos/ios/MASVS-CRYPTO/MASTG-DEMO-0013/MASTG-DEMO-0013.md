---
platform: ios
title: Use of Hardcoded RSA Private Key in SecKeyCreateWithData with r2
code: [swift]
id: MASTG-DEMO-0013
test: MASTG-TEST-0213
---

### Sample

{{ MastgTest.swift # function.asm # decompiled-o1-review.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ sec_hardcoded_rsa.r2 }}

{{ run.sh }}

### Observation

The output reveals a call to `SecKeyCreateWithData` as well as the hardcoded RSA private key within the DATA section of the binary.

{{ output.asm # key.asm }}

### Evaluation

The test fails because a hardcoded RSA private key was found in the code.

**Note**: Using artificial intelligence we're able to decompile the disassembled code and review it. The output is a human-readable version of the assembly code. The AI decompiled code may not perfect and might contain errors but, in this case, it clearly shows the use of `SecKeyCreateWithData` and the associated private key.
