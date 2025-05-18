---
title: SSLSocket Connection to Wrong Host Server Blocked by HostnameVerifier
platform: android
test: MASTG-TEST-0234
code: [kotlin]
kind: pass
---

## Overview

The following sample code demonstrates how to connect to a server that delivers a certificate with a **wrong or invalid hostname** using `SSLSocket` which inherently [doesn't perform any hostname validation checks](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket).


## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool and look for all usages of `SSLSocket` and `HostnameVerifier`.

## Observation

The output contains a list of locations where `SSLSocket` and `HostnameVerifier` are used.

## Evaluation

The test case passes due to the use of a `HostnameVerifier`.

The connection fails as you can see in the logcat output which contains the following exception:

```plaintext
javax.net.ssl.SSLException: Hostname verification failed for host: wrong.host.badssl.com
```
