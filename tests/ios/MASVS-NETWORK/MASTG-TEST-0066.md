---
masvs_v1_id:
- MSTG-NETWORK-2
masvs_v2_id:
- MASVS-NETWORK-1
platform: ios
title: Testing the TLS Settings
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

Remember to [inspect the corresponding justifications](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) to discard that it might be part of the app intended purpose.

It is possible to verify which ATS settings can be used when communicating to a certain endpoint. On macOS the command line utility `nscurl` can be used. A permutation of different settings will be executed and verified against the specified endpoint. If the default ATS secure connection test is passing, ATS can be used in its default secure configuration. If there are any fails in the nscurl output, please change the server side configuration of TLS to make the server side more secure, rather than weakening the configuration in ATS on the client. See the article "Identifying the Source of Blocked Connections" in the [Apple Developer Documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections/identifying_the_source_of_blocked_connections) for more details.

Refer to section "Verifying the TLS Settings" in chapter [Testing Network Communication](../../../Document/0x04f-Testing-Network-Communication.md#verifying-the-tls-settings) for details.
