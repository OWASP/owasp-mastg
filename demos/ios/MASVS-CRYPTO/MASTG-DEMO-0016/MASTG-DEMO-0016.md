---
platform: ios
title: Uses of Broken Hashing Algorithms in CryptoKit with r2
code: [swift]
id: MASTG-DEMO-0016
test: MASTG-TEST-0211
---

### Sample

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Open the app binary with @MASTG-TOOL-0073 with the `-i` option to run this script.

{{ cryptokit_hash.r2 }}

{{ run.sh }}

### Observation

The output contains all uses of `CryptoKit.Insecure` functions in the binary, the xrefs for `Insecure.MD5` and `Insecure.SHA1` and the disassembled code of the region where each of these functions is called.

{{ output.txt }}

### Evaluation

The test fails because the MD5 and SHA1 algorithms were found in the code.

Remember that the context is important when evaluating the use of these algorithms. In some cases, the use of MD5 or SHA1 may be acceptable, for example, when the algorithm is used for checksums or non-cryptographic purposes. In order to determine that you should further analyze the reverse-engineered code and try to learn more about the context in which these algorithms are used.
