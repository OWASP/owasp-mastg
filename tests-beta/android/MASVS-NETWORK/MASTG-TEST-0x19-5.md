---
title: Cleartext traffic observed
platform: network
id: MASTG-TEST-0x19-5
type: [dynamic]
weakness: MASWE-0050
---

## Overview

Intercept the tested app's incoming and outgoing network traffic and make sure that this traffic is encrypted.

## Steps

You can use one of the following approaches:

- Set up @MASTG-TECH-0010 (for Android) or @MASTG-TECH-0062 (for iOS) to capture all traffic and make sure no communication is done in cleartext.
- Capture all traffic with an interception proxy like @MASTG-TOOL-0077, @MASTG-TOOL-0079, or @MASTG-TOOL-0097 and make sure no request is done in cleartext. Interception proxies like Burp and OWASP ZAP will show HTTP(S) traffic only. You can, however, use a Burp plugin such as [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension") or the tool [mitm-relay](https://github.com/jrmdev/mitm_relay "mitm-relay") to decode and visualize communication via XMPP and other protocols.

Note: Some applications may not function correctly with proxies like Burp and OWASP ZAP because of Certificate Pinning. In such a scenario, you can still use the other technique.

## Observation

The output contains a list of cleartext network requests.

## Evaluation

The test case fails if any cleartext requests are logged.
