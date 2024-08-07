---
platform: android
title: Weak Cryptographic Key Generation
tools: @MASTG-TOOL-0109
code: [java]
id: MASTG-DEMO-0012
test: MASTG-TEST-0208
---

### Sample

{{ MastgTest.java }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../../../../rules/mastg-android-weak-crypto-key-generation.yml }}

{{ run.sh }}

### Observation

The rule has identified all the location in the code file where weak cipher key is used.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 2 has initialized the RSA key size of 1024 bits.
- Line 5 using `keyGen.init(64)` which creates a symmetric key with a size of 64 bits (8 bytes).
