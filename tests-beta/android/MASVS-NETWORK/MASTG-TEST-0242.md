---
title: Missing Certificate Pinning in Network Traffic
platform: network
id: MASTG-TEST-0242
type: [network]
weakness: MASWE-0047
---

## Overview

There are multiple ways an application can implement certificate pinning, including via the Android Network Security Config, custom TrustManager implementations, third-party libraries, and native code. Since some implementations might be difficult to identify through static analysis, especially when obfuscation or dynamic code loading is involved, this test uses network interception techniques to determine if certificate pinning is enforced at runtime.

The goal of this test case is to observe whether a [MITM attack]("../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) can intercept HTTPS traffic from the app. A successful MITM interception indicates that the app is either not using certificate pinning or implementing it incorrectly.

If the app is properly implementing certificate pinning, the MITM attack should fail because the app rejects certificates issued by an unauthorized CA, even if the CA is trusted by the system.

## Steps

1. Set up an intercepting proxy, for example @MASTG-TOOL-0077 or @MASTG-TOOL-0097.
2. Install the application on a device connected to that proxy, and intercept the communication.
3. Extract all domains which were intercepted.

## Observation

The output should contain a list of domains for which the interception was successful.

## Evaluation

The test case fails if any relevant domain was intercepted.
