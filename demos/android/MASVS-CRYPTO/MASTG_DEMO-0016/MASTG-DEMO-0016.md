---
platform: android
title: Uses of Insecure Encryption Algorithms in Cipher with semgrep
id: MASTG-DEMO-0016
code: [java]
test: MASTG-TEST-0221
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-weak-encryption.yaml }}

{{ run.sh }}

### Observation

The rule has identified five instances in the code file where insecure encryption algorithms are used.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 37 seems the code utilize insecure DES algorithm.
- Line 56 seems to utilize Cipher.getInstance("AES") defaults to ECB, which  is insecure.
- Line 79 seems the code utilize insecure 3DES algorithm.
