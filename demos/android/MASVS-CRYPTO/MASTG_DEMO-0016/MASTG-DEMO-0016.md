---
platform: android
title: Uses of Insecure Encryption Modes in Cipher with semgrep
id: MASTG-DEMO-0016
code: [java]
test: MASTG-TEST-0221
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/weak-encryption-modes.yaml }}

{{ run.sh }}

### Observation

The rule has identified five instances in the code file where insecure encryption algorithms are used.

{{ output.txt }}

### Evaluation

Review each of the reported instances. The following configuration modes will implies the usage of insecure AES/ECB:

- Line 36 using Cipher.getInstance("AES") defaults to ECB.
- Line 55 using Cipher.getInstance("AES/ECB/NoPadding");.
- Line 76 using Cipher.getInstance("AES/ECB/PKCS5Padding");.
- Line 95 using Cipher.getInstance("AES/ECB/ISO10126Padding");.
- Line 118 using Cipher.getInstance("DES/ECB/PKCS5Padding");.
- Line 141 using Cipher.getInstance("DESede/ECB/PKCS5Padding");.
