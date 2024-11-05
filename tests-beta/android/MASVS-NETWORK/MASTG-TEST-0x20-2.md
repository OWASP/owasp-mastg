---
title: Insecure TLS Protocols in Network Traffic
platform: network
id: MASTG-TEST-0x20-2
type: [network]
weakness: MASWE-0050
---

## Overview

When you analyze the enabled TLS protocol versions statically, the result can be that multiple versions are enabled in the application. Depending on the configuration of the server, one of those versions is chosen.

To reveal the actually used version, you can observe the traffic on the network, which will show the version the application and the server agreed on.

If static analysis is not possible, analyzing the used TLS version on a network level can be a possible way of revealing an insecure verson.

## Steps

1. Set up @MASTG-TECH-0010 (for Android) or @MASTG-TECH-0062 (for iOS).
2. View the TLS version e.g., using @MASTG-TOOL-0081.

## Observation

The output shows the actually used TLS version.

## Evaluation

The test case fails if any ["insecure TLS version"](https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/#recommended-tls-settings) is used.
