---
platform: android
title: Cryptographic Key Generation With Insufficient Key Length
code: [java]
id: MASTG-DEMO-0012
test: MASTG-TEST-0208
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-key-generation-with-insufficient-key-length.yml }}

{{ run.sh }}

### Observation

The rule has identified some instances in the code file where cryptographic keys are being generated. The specified line numbers can be located in the reverse-engineered code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test fails because the key size of the RSA key is set to `1024` bits, and the size of the AES key is set to `128`, which is considered insufficient in both cases.
