---
platform: android
title: Improper use of checkServerTrusted
id: MASTG-DEMO-0033
code: [java]
test: MSTG-TEST-0234-1
---

### Sample

{{ MastgTest.kt # MastgTest.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-checkservertrusted.yml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code file where `checkServerTrusted` is used without the use of exception handling.The specified line numbers can be located in the original code for further investigation and remediation.

### Evaluation

Review each of the reported instances.

- Line 128-133 and line 214-219 contains the checkServerTrusted function meant to throw an CertificateException, but as the method only contain a log statement, no such exception will be thrown. This will effectively ensure that all server certificate issues will be muted by the application.