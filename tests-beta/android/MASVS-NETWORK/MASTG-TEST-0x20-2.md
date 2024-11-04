---
title: Usage of Insecure TLS Protocols
platform: network
id: MASTG-TEST-0x20-2
type: [network]
weakness: MASWE-0050
---

## Overview

You can observe the TLS protocol the app uses by observing the traffic on the network.

## Steps

1. Set up @MASTG-TECH-0010 (for Android) or @MASTG-TECH-0062 (for iOS).
2. View the TLS version e.g., using @MASTG-TOOL-0081.

## Observation

The output shows the actually used TLS version.

## Evaluation

The evaluation fails if any ["insecure TLS version"](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/#recommended-tls-settings) is used.
