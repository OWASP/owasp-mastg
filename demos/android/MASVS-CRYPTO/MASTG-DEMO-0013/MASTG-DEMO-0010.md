---
platform: android
title: Hardcoded-crypto-keys-usage
tools: [semgrep]
code: [java]
---

### Sample

{{ MastgTest.java }}

### Steps

Let's run our semgrep rule against the sample code.

{{ ../../../../rules/mastg-android-hardcoded-crypto-keys-usage.yaml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code file where hardcoded keys is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.

- Line 7 ,  A hardocoded key is used directly.
- Line 14 , the variable 'encryptionKey' which stores the hardcoded encryption key is getting used.
- Line 25 , the argument passed 'secretKey'  stores the hardcoded encryption key.
