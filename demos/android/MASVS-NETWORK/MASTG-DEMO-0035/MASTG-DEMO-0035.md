---
platform: android
title: Improper use of the onReceivedSslError handler
id: MASTG-DEMO-0035
code: [kotlin]
test: MSTG-TEST-0234-3
---

### Sample

{{ MastgTestWebView.kt # MastgTestWebView.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-onreceivedsslerror.yml }}

{{ run.sh }}

### Observation

The rule has identified one instances in the code where `onReceivedSslError` not is implemented properly.

### Evaluation

The test fails because of the presence of the `handler.proceed()` on line 91 in the `onReceivedSslError` method (lines 79-92), as well as the absence of exceptions being thrown.

By doing this, the app is effectively ignoring every TLS error even though we can see that the expired certificate error is logged (see @MASTG-TECH-0009):

{{ logcat.txt }}
