---
platform: ios
title: Use of Hardcoded ECDSA Private Key in CryptoKit with r2
code: [swift]
id: MASTG-DEMO-0014
test: MASTG-TEST-0213
---

### Sample

{{ MastgTest.swift # function.asm # decompiled-o1-review.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ cryptokit_hardcoded_ecdsa.r2 }}

{{ run.sh }}

### Observation

The output reveals the different uses of `CryptoKit.P256.Signing.PrivateKey` functions, especially `sym.imp.CryptoKit.P256.Signing.PrivateKey.rawRepresentation` which is used to extract the raw representation of the private key. The output also reveals the hardcoded ECDSA private key within the binary's DATA section.

{{ output.asm # key.asm }}

### Evaluation

The test fails because a hardcoded ECDSA private key was found in the code.

**Note**: Using artificial intelligence we're able to decompile the disassembled code and review it. The output is a human-readable version of the assembly code. The AI decompiled code may not perfect and might contain errors but, in this case, it clearly shows the use of `CryptoKit.P256.Signing.PrivateKey` and the associated private key.
