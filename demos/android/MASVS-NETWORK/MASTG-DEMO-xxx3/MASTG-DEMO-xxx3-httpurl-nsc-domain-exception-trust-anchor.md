---
title: Connection to Self-Signed Server with HttpsURLConnection and Per-Domain Network Security Config Exception and trust-anchor
platform: android
works: yes
kind: fail
---

## Overview

The following sample code demonstrates how to connect to a server with a **self-signed certificate** using `HttpsURLConnection` and adding an exception in the network security configuration file to disable certificate validation for the specified domain and a trust-anchor for the self-signed certificate.

**Obtain the Certificate**: Extract the self-signed certificate in `.crt` or `.pem` format from the server and place it in your app's `res/raw` directory.

```bash
echo | openssl s_client -connect self-signed.badssl.com:443 | openssl x509 > selfsigned.crt
```

If the app tries to connect to another domain, e.g. expired.badssl.com, the connection will fail with an exception like:

```plaintext
javax.net.ssl.SSLHandshakeException: Unacceptable certificate: CN=COMODO RSA Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
```
