---
masvs_v1_id:
- MSTG-STORAGE-4
masvs_v2_id:
- MASVS-STORAGE-2
platform: android
title: Determining Whether Sensitive Data Is Shared with Third Parties via Embedded
    Services
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

To determine whether API calls and functions provided by the third-party library are used according to best practices, review their source code, requested permissions and check for any known vulnerabilities.

All data that's sent to third-party services should be anonymized to prevent exposure of PII (Personal Identifiable Information) that would allow the third party to identify the user account. No other data (such as IDs that can be mapped to a user account or session) should be sent to a third party.

## Dynamic Analysis

Check all requests to external services for embedded sensitive information.
To intercept traffic between the client and server, you can perform dynamic analysis by launching a [Machine-in-the-Middle (MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) attack with @MASTG-TOOL-0077 or @MASTG-TOOL-0079. Once you route the traffic through the interception proxy, you can try to sniff the traffic that passes between the app and server. All app requests that aren't sent directly to the server on which the main function is hosted should be checked for sensitive information, such as PII in a tracker or ad service.
