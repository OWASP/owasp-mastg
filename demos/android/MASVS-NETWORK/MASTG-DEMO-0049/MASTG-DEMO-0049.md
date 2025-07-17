---
title: SSLSocket Connection to Wrong Host Server Blocked by HostnameVerifier
platform: android
id: MASTG-DEMO-0049
test: MASTG-TEST-0234
code: [kotlin]
kind: pass
---

## Overview

The following sample code demonstrates how to connect to a @MASTG-TOOL-0143 server that delivers a certificate with a **wrong or invalid hostname** using `SSLSocket` which inherently [doesn't perform any hostname validation checks](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket).

However, the code implements a custom `HostnameVerifier` that performs hostname verification, thus blocking the connection to the server with the wrong hostname.

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

The test case passes due to the use of a `HostnameVerifier`.

As expected, **the connection aborts** as you can see in the logcat output which contains the following exception:

```plaintext
javax.net.ssl.SSLException: Hostname verification failed for host: wrong.host.badssl.com
```
