---
platform: android
title: Weak Cryptographic Key Generation
code: [java]
id: MASTG-DEMO-0012
test: MASTG-TEST-0208
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-weak-crypto-key-generation.yml }}

{{ run.sh }}

### Observation

The rule has identified some instances in the code file where an non-random source is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.
