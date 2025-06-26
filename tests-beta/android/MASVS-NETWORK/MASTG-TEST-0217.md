---
title: Insecure TLS Protocols Explicitly Allowed in Code
platform: android
id: MASTG-TEST-0217
type: [static]
weakness: MASWE-0050
profiles: [L1, L2]
---

## Overview

The Android Network Security Configuration does not provide direct control over specific TLS versions (unlike [iOS](https://developer.apple.com/documentation/bundleresources/information_property_list/nsexceptionminimumtlsversion)), and starting with Android 10, [TLS v1.3 is enabled by default](https://developer.android.com/privacy-and-security/security-ssl#Updates%20to%20SSL) for all TLS connections.

There are still several ways to enable insecure versions of TLS, including:

### Java Sockets

An app can obtain an SSLContext using an insecure TLS protocol by calling `SSLContext.getInstance("TLSv1.1")` and can also enable specific, potentially insecure, protocol versions using the API call `javax.net.ssl.SSLSocket.setEnabledProtocols(String[] protocols)`.

### Third-party Libraries

Some third-party libraries, such as [OkHttp](https://square.github.io/okhttp/), [Retrofit](https://square.github.io/retrofit/) or Apache HttpClient, provide custom configurations for TLS protocols. These libraries may allow enabling outdated protocols if not carefully managed:

For example, using `ConnectionSpec.COMPATIBLE_TLS` in OkHttp (via `okhttp3.ConnectionSpec.Builder.connectionSpecs(...)`) can lead to insecure TLS versions, like TLS 1.1, being enabled by default in certain versions. Refer to OkHttp's [configuration history](https://square.github.io/okhttp/security/tls_configuration_history/) for details on supported protocols.

The API call `okhttp3.ConnectionSpec.Builder.tlsVersions(...)` can also be used to set the enabled protocols ([OkHttp documentation](https://square.github.io/okhttp/features/https/)).

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool on the reverse engineered app targeting calls to APIs setting the TLS protocol.

## Observation

The output contains a list of all enabled TLS versions in the above mentioned API calls.

## Evaluation

The test case fails if any [insecure TLS version](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/#recommended-tls-settings) is directly enabled, or if the app enabled any settings allowing the use of outdated TLS versions, such as `okhttp3.ConnectionSpec.COMPATIBLE_TLS`.
