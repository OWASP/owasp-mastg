---
title: Connection to Self-Signed Server with HttpsURLConnection Blocked
platform: android
works: yes
kind: pass
---

## Overview

The following sample code demonstrates how to connect to a server with a **self-signed certificate** using `HttpsURLConnection` and how the connection fails with an exception like:

```plaintext
javax.net.ssl.SSLHandshakeException: java.security.cert.CertPathValidatorException: Trust anchor for certification path not found.
```
