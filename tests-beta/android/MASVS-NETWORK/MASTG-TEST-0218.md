---
title: Insecure TLS Protocols in Network Traffic
platform: network
id: MASTG-TEST-0218
type: [network]
weakness: MASWE-0050
profiles: [L1, L2]
---

## Overview

While static analysis can identify configurations that allow insecure TLS versions, it may not accurately reflect the actual protocol used during live communications. This is because TLS version negotiation occurs between the client (app) and the server at runtime, where they agree on the most secure, mutually supported version.

By capturing and analyzing real network traffic, you can observe the TLS version actually negotiated and in use. This approach provides an accurate view of the protocol's security, accounting for the server's configuration, which may enforce or limit specific TLS versions.

In cases where static analysis is either incomplete or infeasible, examining network traffic can reveal instances where insecure TLS versions (e.g., TLS 1.0 or TLS 1.1) are actively in use.

## Steps

1. Set up @MASTG-TECH-0010 (for Android) or @MASTG-TECH-0062 (for iOS).
2. View the TLS version e.g., using @MASTG-TOOL-0081.

## Observation

The output shows the actually used TLS version.

## Evaluation

The test case fails if any [insecure TLS version](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/#recommended-tls-settings) is used.
