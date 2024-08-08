---
platform: android
title: Common Uses of Insecure Random APIs
id: MASTG-DEMO-0008
code: [java]
test: MASTG-TEST-0205
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-non-random-use.yaml }}

{{ run.sh }}

### Observation

The rule has identified some instances in the code file where an non-random source is used. The specified line numbers can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

Review each of the reported instances.
