---
platform: android
title: Use of Hardcoded AES Key in SecretKeySpec with semgrep
id: MASTG-DEMO-0017
test: MASTG-TEST-0212
tools: [semgrep]
code: [java]
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-hardcoded-crypto-keys-usage.yml }}

{{ run.sh }}

### Observation

The rule has identified one instance in the code file where hardcoded keys is used. The specified line numbers can be located in the reverse-engineered code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test fails because hardcoded cryptographic keys are present in the code. Specifically:

- On line 24, a byte array that represents a cryptographic key is directly hardcoded into the source code.
- This hardcoded key is then used on line 26 to create a `SecretKeySpec`.
- Additionally, on line 30, another instance of hardcoded data is used to create a separate `SecretKeySpec`.
