---
platform: android
title: Uses of Broken Encryption Modes in Cipher with semgrep
id: MASTG-DEMO-0023
code: [kotlin]
test: MASTG-TEST-0232
---

### Sample

The code snippet below shows sample code contains use of broken encryption modes.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-broken-encryption-modes.yaml }}

{{ run.sh }}

### Observation

The rule has identified six instances in the code file where broken encryption modes are used. The specified line numbers can be located in the reverse-engineered code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test fails since the output contains several instances of the ECB mode of AES in different transformations explicitly or implicitly (ECB is the default mode for AES if not specified).

See @MASTG-TEST-0232 for more information.
