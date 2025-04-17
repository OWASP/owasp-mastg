---
platform: android
title: Improper use of the onReceivedSslError handler
id: MASTG-DEMO-0035
code: [java]
test: MSTG-TEST-0234-3
---

### Sample

{{ MastgTest.kt # MastgTest.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-onreceivedsslerror.yml }}

{{ run.sh }}

### Observation

The rule has identified one instances in the code where `onReceivedSslError` not is implemented properly.

### Evaluation

Review each of the reported instances.

- Line 79-92 contains the `onReceivedSslError` method. At the end, on line 91, there is a `handler.proceed()`. There are no exceptions being thrown which means that TLS errors are being ignored.
