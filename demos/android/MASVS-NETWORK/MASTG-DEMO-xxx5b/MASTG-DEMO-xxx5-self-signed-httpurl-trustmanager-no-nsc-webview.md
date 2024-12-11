---
title: Connection to Self-Signed Server with custom Trust Manager, HttpsURLConnection and no Changes in Network Security Config from a WebView
platform: android
works: yes
kind: fail
---

## Overview

The following sample code demonstrates how to connect from a WebView to a server with a **self-signed certificate** using `HttpsURLConnection` and a custom `TrustManager` to bypass certificate validation checks. This approach allows developers to connect to servers with invalid or self-signed certificates without modifying the Network Security Configuration (NSC) settings.

In this case the TrustManager is created with a custom implementation that trusts all certificates.

If it weren't for the custom TrustManager, the connection would fail with an exception like:

```plaintext
Intercepting URL: https://self-signed.badssl.com/
Attempting to fetch URL: https://self-signed.badssl.com/
tagSocket(194) with statsTag=0xffffffff, statsUid=-1
Error fetching URL: javax.net.ssl.SSLHandshakeException: java.security.cert.CertPathValidatorException: Trust anchor for certification path not found.
Failed to validate the certificate chain, error: java.security.cert.CertPathValidatorException: Trust anchor for certification path not found.
[ERROR:ssl_client_socket_impl.cc(996)] handshake failed; returned -1, SSL error code 1, net_error -202
```

We can add a Network Security Configuration to allow connections to the self-signed server using a trust anchor and the connection will succeed.

Also, we included CORS headers, if we remove them, the connection will fail with an exception like:

```plaintext
Intercepting URL: https://self-signed.badssl.com/
Attempting to fetch URL: https://self-signed.badssl.com/
tagSocket(161) with statsTag=0xffffffff, statsUid=-1
Header: null -> [HTTP/1.1 200 OK]
Header: Cache-Control -> [no-store]
Header: Connection -> [keep-alive]
Header: Content-Type -> [text/html]
Header: Date -> [Mon, 09 Dec 2024 10:08:39 GMT]
Header: ETag -> [W/"673f94fa-1f6"]
Header: Last-Modified -> [Thu, 21 Nov 2024 20:15:54 GMT]
Header: Server -> [nginx/1.10.3 (Ubuntu)]
Header: Transfer-Encoding -> [chunked]
Header: X-Android-Received-Millis -> [1733738918948]
Header: X-Android-Response-Source -> [NETWORK 200]
Header: X-Android-Selected-Protocol -> [http/1.1]
Header: X-Android-Sent-Millis -> [1733738918808]
JS Console: Access to XMLHttpRequest at 'https://self-signed.badssl.com/' from origin 'null' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.
```
