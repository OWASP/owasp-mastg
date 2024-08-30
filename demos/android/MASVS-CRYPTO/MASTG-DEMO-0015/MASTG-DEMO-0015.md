---
platform: android
title: Use of Hardcoded AES Key in SecretKeySpec with semgrep
tools: [semgrep]
code: [java]
---

### Sample

{{ MastgTest.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-hardcoded-crypto-keys-usage.yaml }}

{{ run.sh }}

### Observation

The rule has identified one instance in the code file where hardcoded keys is used. The specified line numbers can be located in the reverse-engineered code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test fails because a hardcoded AES key was found in the code.
