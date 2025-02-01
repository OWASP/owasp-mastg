---
platform: android
title: Uses of Insecure Encryption Modes in Cipher with semgrep
id: MASTG-DEMO-0023
code: [kotlin]
test: MASTG-TEST-0221
---

### Sample

The code snippet below shows sample code contains use of insecure encryption modes.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-weak-encryption-modes }}

{{ run.sh }}

### Observation

The rule has identified six instances in the code file where insecure encryption modes are used. The specified line numbers can be located in the reverse-engineered code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test fails since the output contains several instances of the ECB mode of AES in different transformations explicitly or implicitly (ECB is the default mode for AES if not specified).

The [ECB mode of operation](https://csrc.nist.gov/pubs/sp/800/38/a/final) is generally discouraged [see NIST announcement in 2023](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a) due to its inherent security weaknesses. While not explicitly prohibited, its use is limited and advised against in most scenarios. Google Play Store policies also [restrict the use of ECB mode](https://support.google.com/faqs/answer/10046138) for encryption.
