---
platform: android
title: Find Weak Cryptographic Key length 
tools: [semgrep]
code: [java]
---

### Sample

{{ key-length.java }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../rules/mastg-weak-crypto-key-generation.yml }}

{{ run.sh }}

### Observation

The rule has identified all the location in the code file where weak cipher key is used.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 2 has inialized the RSA key size of 1024 bits.
- Line 9 using `keyGen.init(64)` initializer creates a symmetric key with a size of 64 bits (8 bytes).