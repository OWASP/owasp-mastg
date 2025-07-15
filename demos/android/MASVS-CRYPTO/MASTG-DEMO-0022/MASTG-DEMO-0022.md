---
platform: android
title: Uses of Broken Symmetric Encryption Algorithms in Cipher with semgrep
id: MASTG-DEMO-0022
code: [kotlin]
test: MASTG-TEST-0221
---

### Sample

The code snippet below shows sample code contains use of insecure encryption algorithms.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-broken-encryption-algorithms.yaml }}

{{ run.sh }}

### Observation

The rule has identified several instances in the code file where broken encryption algorithms are used. The specified line numbers can be located in the reverse-engineered code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test fails due to the use of broken encryption algorithms, specifically DES, 3DES, RC4 and Blowfish.

See @MASTG-TEST-0221 for more information.
