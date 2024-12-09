---
title: Connection to Wrong Host Server with SSLSocket without Enabling hostname verification
platform: android
works: yes
kind: pass
---

## Overview

The following sample code demonstrates how to connect to a server that delivers a certificate with a **wrong or invalid hostname** using `SSLSocket` which inherently [doesn't perform any hostname validation checks](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket). This approach uses a HostnameVerifier, so the connection fails with an exception like:

```plaintext
javax.net.ssl.SSLException: Hostname verification failed for host: wrong.host.badssl.com
```
