---
platform: android
title: Improper use of the HostnameVerifier
id: MASTG-DEMO-0034
code: [java]
test: MSTG-TEST-0234-2
---

### Sample

{{ MastgTest.kt # MastgTest.kt }}

### Steps

Let's run our @MASTG-TOOL-0110 rule against the sample code.

{{ ../../../../rules/mastg-android-network-hostname-verification.yml }}

{{ run.sh }}

### Observation

The rule has identified two instances in the code where `HostnameVerifier` not is implemented properly.

### Evaluation

Review each of the reported instances.

- Line 151-154 contains a synthetic class that logs a statement and return true effectively muting any host name issues. 
- Line 236 contains a ALLOW_ALL_HOSTNAME_VERIFIER from org.apache.http.conn.ssl.SSLSocketFactory. This should only be used for testing as it will ignore host name issues and is marked deprecated.