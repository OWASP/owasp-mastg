---
masvs_v1_id:
- MSTG-STORAGE-4
masvs_v2_id:
- MASVS-STORAGE-2
platform: ios
title: Determining Whether Sensitive Data Is Shared with Third Parties
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0206, MASTG-TEST-0281]
deprecation_note: New version available in MASTG V2
---

## Overview

Sensitive information might be leaked to third parties by several means. On iOS typically via third-party services embedded in the app.

The features these services provide can involve tracking services to monitor the user's behavior while using the app, selling banner advertisements, or improving the user experience.

The downside is that developers don't usually know the details of the code executed via third-party libraries. Consequently, no more information than is necessary should be sent to a service, and no sensitive information should be disclosed.

Most third-party services are implemented in two ways:

- with a standalone library
- with a full SDK

## Static Analysis

To determine whether API calls and functions provided by the third-party library are used according to best practices, review their source code, requested permissions and check for any known vulnerabilities.

All data that's sent to third-party services should be anonymized to prevent exposure of PII (Personal Identifiable Information) that would allow the third party to identify the user account. No other data (such as IDs that can be mapped to a user account or session) should be sent to a third party.

## Dynamic Analysis

Check all requests to external services for embedded sensitive information.
To intercept traffic between the client and server, you can perform dynamic analysis by launching a [Machine-in-the-Middle (MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) attack (@MASTG-TECH-0062), for example using @MASTG-TOOL-0077 or @MASTG-TOOL-0079. Once you route the traffic through the interception proxy, you can try to sniff the traffic that passes between the app and server. All app requests that aren't sent directly to the server on which the main function is hosted should be checked for sensitive information, such as PII in a tracker or ad service.
