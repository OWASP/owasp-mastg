---
title: SSLSocket Connection to Wrong Host Server Allowed by Lack of HostnameVerifier
platform: android
id: MASTG-DEMO-0048
test: MASTG-TEST-0234
code: [kotlin]
kind: fail
---

## Overview

The following sample code demonstrates how to connect to a @MASTG-TOOL-0143 server that delivers a certificate with a **wrong or invalid hostname** using `SSLSocket`, which inherently [doesn't perform any hostname validation checks](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket).

**Note:** The connection succeeds even if the app has a fully secure Network Security Configuration (NSC) in place because `SSLSocket` is not affected by it.

{{ MastgTest.kt # MastgTest_reversed.java }}

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `SSLSocket` and `HostnameVerifier`.

{{ ../../../../rules/mastg-android-ssl-socket-hostnameverifier.yml }}

{{ run.sh }}

## Observation

The output contains a list of locations where `SSLSocket` and `HostnameVerifier` are used.

{{ output.txt }}

## Evaluation

The test case fails due to the missing `HostnameVerifier`.

**Note:** If the app were to use a `HostnameVerifier`, the **connection would abort** with an exception like the following, which can be read in the logcat output:

```plaintext
javax.net.ssl.SSLException: Hostname verification failed for host: wrong.host.badssl.com
```
