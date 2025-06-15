---
platform: android
title: Improper use of checkServerTrusted
id: MASTG-DEMO-0033
code: [kotlin]
test: MSTG-TEST-0234-1
---

### Sample

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-checkservertrusted.yml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code file where `checkServerTrusted` is used without the use of exception handling. The specified line numbers can be located in the original code for further investigation and remediation.

### Evaluation

Review each of the reported instances.

- Line 128-133 and line 214-219 contains the `checkServerTrusted` function which doesn't throw any `CertificateException`, as it only contains a log statement. This is dangerous as it suppresses all server certificate issues.
