---
title: Connection to Wrong Host Server with custom HostnameVerifier, HttpsURLConnection and no Changes in Network Security Config disabling hostname verification
platform: android
works: yes
kind: fail
---

## Overview

The following sample code demonstrates how to connect to a server that delivers a certificate with a **wrong or invalid hostname** using `HttpsURLConnection` and a custom `HostnameVerifier` to bypass hostname validation checks. This approach doesn't require modifying the Network Security Configuration (NSC) settings.

If it weren't for the custom HostnameVerifier, the connection would fail with an exception like:

```plaintext
javax.net.ssl.SSLPeerUnverifiedException: Hostname wrong.host.badssl.com not verified:
    certificate: sha1/C5Dn425Gc9B9XyQntlokBd5uA50=
    DN: CN=*.badssl.com
    subjectAltNames: [*.badssl.com, badssl.com]
```
