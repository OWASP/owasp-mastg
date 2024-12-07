---
title: Connection to Self-Signed Server with SSL Socket and Trust Manager
platform: android
works: yes
kind: fail
---

The sample code demonstrates how to establish a connection to a self-signed server using an `SSLSocket` and a custom `TrustManager` in Android. This approach allows developers to bypass certificate validation checks and connect to servers with invalid or self-signed certificates.

By using a custom `TrustManager`, the app effectively bypasses the default Network Security Configuration (NSC) settings and can trust any certificate, including self-signed certificates.
