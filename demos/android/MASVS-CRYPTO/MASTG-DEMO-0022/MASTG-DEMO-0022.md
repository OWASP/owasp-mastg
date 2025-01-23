---
platform: android
title: Uses of Insecure Encryption Algorithms in Cipher with semgrep
id: MASTG-DEMO-0022
code: [kotlin]
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-weak-encryption-algorithms.yaml }}

{{ run.sh }}

### Observation

The rule has identified five instances in the code file where an insecure encryption is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test fails since several instances of weak encryption algorithms were found:

- Line 36 utilize insecure DES algorithm.
- Line 59 utilize insecure 3DES algorithm.
