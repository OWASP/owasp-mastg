---
masvs_v1_id:
- MSTG-NETWORK-3
masvs_v2_id:
- MASVS-NETWORK-1
platform: ios
title: Testing Endpoint Identity Verification
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

Using TLS to transport sensitive information over the network is essential for security. However, encrypting communication between a mobile application and its backend API is not trivial. Developers often decide on simpler but less secure solutions (e.g., those that accept any certificate) to facilitate the development process, and sometimes these weak solutions make it into the production version, potentially exposing users to [Machine-in-the-Middle (MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) attacks. See ["CWE-295: Improper Certificate Validation"](https://cwe.mitre.org/data/definitions/295.html "CWE-295: Improper Certificate Validation").

These are some of the issues should be addressed:

- Check if the app links against an SDK older than iOS 9.0. In that case ATS is disabled no matter which version of the OS the app runs on.
- Verify that a certificate comes from a trusted source, i.e. a trusted CA (Certificate Authority).
- Determine whether the endpoint server presents the right certificate.

Make sure that the hostname and the certificate itself are verified correctly. Examples and common pitfalls are available in the [official Apple documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections "Preventing Insecure Network Connections").

We highly recommend supporting static analysis with the dynamic analysis. If you don't have the source code or the app is difficult to reverse engineer, having a solid dynamic analysis strategy can definitely help. In that case you won't know if the app uses low or high-level APIs but you can still test for different trust evaluation scenarios (e.g. "does the app accept a self-signed certificate?").

## Dynamic Analysis

Our test approach is to gradually relax security of the SSL handshake negotiation and check which security mechanisms are enabled.

1. Having Burp set up as a proxy, make sure that there is no certificate added to the trust store (**Settings** -> **General** -> **Profiles**) and that tools like SSL Kill Switch are deactivated. Launch your application and check if you can see the traffic in Burp. Any failures will be reported under 'Alerts' tab. If you can see the traffic, it means that there is no certificate validation performed at all. If however, you can't see any traffic and you have an information about SSL handshake failure, follow the next point.
2. Now, install the Burp certificate, as explained in [Burp's user documentation](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp\'s CA Certificate in an iOS Device"). If the handshake is successful and you can see the traffic in Burp, it means that the certificate is validated against the device's trust store, but no pinning is performed.

If executing the instructions from the previous step doesn't lead to traffic being proxied, it may mean that certificate pinning is actually implemented and all security measures are in place. However, you still need to bypass the pinning in order to test the application. Please refer to @MASTG-TECH-0064 for more information on this.
