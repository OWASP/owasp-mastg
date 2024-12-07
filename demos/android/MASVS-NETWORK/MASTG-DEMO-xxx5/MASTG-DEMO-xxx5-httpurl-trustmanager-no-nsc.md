---
title: Connection to Self-Signed Server with custom Trust Manager, HttpsURLConnection and no Changes in Network Security Config
platform: android
works: yes
kind: fail
---

## Overview

The following sample code demonstrates how to connect to a server with a **self-signed certificate** using `HttpsURLConnection` and a custom `TrustManager` to bypass certificate validation checks. This approach allows developers to connect to servers with invalid or self-signed certificates without modifying the Network Security Configuration (NSC) settings.

In this case the TrustManager is created with a custom implementation that trusts all certificates.

If it weren't for the custom TrustManager, the connection would fail with an exception like:

```plaintext
javax.net.ssl.SSLHandshakeException: java.security.cert.CertPathValidatorException: Trust anchor for certification path not found.
```
