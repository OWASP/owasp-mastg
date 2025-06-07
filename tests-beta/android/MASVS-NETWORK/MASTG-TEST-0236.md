---
title: Cleartext Traffic Observed on the Network
platform: network
id: MASTG-TEST-0236
type: [dynamic]
weakness: MASWE-0050
profiles: [L1, L2]
---

## Overview

This test intercepts the app's incoming and outgoing network traffic, and checks for any cleartext communication.
Whilst the static checks can only show _potential_ cleartext traffic, this dynamic test shows all communication the application definitely makes.

!!! warning Limitation
    - Intercepting traffic on a network level will show all traffic _the device_ performs, not only the single app. Linking the traffic back to a specific app can be difficult, especially when more apps are installed on the device.
    - Linking the intercepted traffic back to specific locations in the app can be difficult and requires manual analysis of the code.
    - Dynamic analysis works best when you interact extensively with the app. But even then there could be corner cases which are difficult or impossible to execute on every device. The results from this test therefore are likely not exhaustive.

## Steps

You can use one of the following approaches:

- Set up @MASTG-TECH-0010 (for Android) or @MASTG-TECH-0062 (for iOS) to capture all traffic.
- Set up @MASTG-TECH-0011 (for Android) or @MASTG-TECH-0063 (for iOS) to capture all traffic.

**Notes**:

- Interception proxies will show HTTP(S) traffic only. You can, however, use some tool-specific plugins such as [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension) or other tools like @MASTG-TOOL-0078 to decode and visualize communication via XMPP and other protocols.
- Some apps may not function correctly with proxies like Burp and @MASTG-TOOL-0079 because of certificate pinning. In such a scenario, you can still use basic network sniffing to detect cleartext traffic. Otherwise, you can try to disable pinning (see @MASTG-TECH-0012 for Android and @MASTG-TECH-0064 for iOS)

## Observation

The output contains the captured network traffic.

## Evaluation

The test case fails if any clear text traffic originates from the target app.

**Note**: This can be challenging to determine because traffic can potentially come from any app on the device. See the [Overview](#overview) section.
