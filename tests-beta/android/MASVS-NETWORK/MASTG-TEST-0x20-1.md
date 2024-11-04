---
title: Usage of Insecure TLS Protocols
platform: android
id: MASTG-TEST-0x20-1
type: [static]
weakness: MASWE-0050
---

## Overview

Multiple ways to enable insecure protocols exist in Android:

### Java Sockets

If the app uses Java Sockets, the API call `javax.net.ssl.SSLSocket.setEnabledProtocols(String[] protocols)` sets the enabled protocols.

### OkHttp

If the app uses OkHttp and sets the allowed TLS protocols to `ConnectionSpec.COMPATIBLE_TLS` by calling `okhttp3.ConnectionSpec.Builder.connectionSpecs(...)`, this results in one or more insecure TLS versions (e.g, in TLS v1.1 (see ["configuration history"](https://square.github.io/okhttp/security/tls_configuration_history/#okhttp-313))).

The API call `okhttp3.ConnectionSpec.Builder.tlsVersions(...)` (["OkHttp documentation"](https://square.github.io/okhttp/features/https/)) can also be used to set the enabled protocols.

## Steps

1. Reverse engineer the app (@MASTG-TECH-0017).
2. Run a static analysis (@MASTG-TECH-0014) tool on the reverse engineered app targeting calls to APIs setting the TLS protocol.

## Observation

The output contains a list of all enabled TLS versions in the above mentioned API calls.

## Evaluation

The evaluation fails if any ["insecure TLS version"](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/#recommended-tls-settings) is directly enabled, or if the app enabled `okhttp3.ConnectionSpec.COMPATIBLE_TLS`.s
