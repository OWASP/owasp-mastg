---
title: Insecure TLS Protocols Explicitly Allowed in Code
platform: android
id: MASTG-TEST-0x20-1
type: [static]
weakness: MASWE-0050
---

## Overview

The Android Network Security Configuration does not provide direct control over specific TLS versions (unlike ["iOS"](https://developer.apple.com/documentation/bundleresources/information_property_list/nsexceptionminimumtlsversion)), and starting with Android 10, the secure TLS version 1.3 is enabled by default for all TLS connections.

There are still several ways to enable insecure versions of TLS, including:

### Java Sockets

An app can obtain an SSLContext using an insecure TLS protocol by calling `SSLContext.getInstance("TLSv1.1")` and can also enable specific, potentially insecure, protocol versions using the API call `javax.net.ssl.SSLSocket.setEnabledProtocols(String[] protocols)`.

### Third-party Libraries

Other libraries, such as [OkHttp](https://square.github.io/okhttp/), [Retrofit](https://square.github.io/retrofit/) or Apache HttpClient may have their own configurations for TLS protocols.

For example, if the app uses OkHttp and sets the allowed TLS protocols to `ConnectionSpec.COMPATIBLE_TLS` by calling `okhttp3.ConnectionSpec.Builder.connectionSpecs(...)`, this results in one or more insecure TLS versions (e.g, in TLS v1.1 (see ["configuration history"](https://square.github.io/okhttp/security/tls_configuration_history/#okhttp-313))).

The API call `okhttp3.ConnectionSpec.Builder.tlsVersions(...)` (["OkHttp documentation"](https://square.github.io/okhttp/features/https/)) can also be used to set the enabled protocols.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool on the reverse engineered app targeting calls to APIs setting the TLS protocol.

## Observation

The output contains a list of all enabled TLS versions in the above mentioned API calls.

## Evaluation

The test case fails if any ["insecure TLS version"](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/#recommended-tls-settings) is directly enabled, or if the app enabled any settings allowing the use of outdated TLS versions, such as `okhttp3.ConnectionSpec.COMPATIBLE_TLS`.s
