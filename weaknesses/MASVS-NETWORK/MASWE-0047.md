---
title: Insecure Identity Pinning
id: MASWE-0047
alias: insecure-pinning
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-NETWORK-4]
  masvs-v2: [MASVS-NETWORK-2]
  cwe: [295]
status: new
---

## Overview

[Identity pinning (aka. certificate pinning, public key pinning or TLS pinning)](../../Document/0x04f-Testing-Network-Communication/#restricting-trust-identity-pinning) refers to associating a mobile app with a specific cryptographic identity, such as a certificate or public key to ensure that the app only communicates with trusted servers.

When a mobile app does not implement certificate pinning, or if it is implemented incorrectly, the app remains vulnerable to [Machine-in-the-Middle (MITM)](../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) attacks which enable attackers to intercept and modify the communication between the app and the intended server. This occurs because when the app is presented a fraudulent certificate that the app may unknowingly trust, thereby gaining access to sensitive data or injecting malicious content into the data stream.

**Limitations**: Certificate pinning adds a layer of trust verification by ensuring that the app only accepts connections to servers with specific, pre-determined certificates or public keys. This reduces the risk of unauthorized interception, even if a trusted Certificate Authority (CA) is compromised. However, it is not foolproof:

- Attackers who can reverse-engineer the app may analyze and remove or modify the pre-defined pins or the certificate pinning logic to permanently bypass the checks.
- Attackers who can perform @MASTG-TECH-0051 techniques to manipulate the app and bypass pinning checks.

This highlights the importance of implementing certificate pinning **alongside other security measures** to enhance the app's resistance to advanced threats.

## Impact

- **Data Interception**: Attackers can capture and read sensitive information transmitted over the network.
- **Data Manipulation**: Attackers might alter data in transit, causing corruption or injecting malicious content.
- **Data Exposure**: Sensitive information can be compromised.
- **Denial of Service**: Incorrect pinning may cause legitimate connections to fail, leading to service disruptions for users. For example, if a pinned certificate expires and is not updated, the app may be unable to establish secure connections.

## Modes of Introduction

- **Improper Configuration of Pinning Libraries**: Misconfiguring libraries like TrustKit, OkHttp's `CertificatePinner`, Volley, or AFNetworking's `SSLPinningMode`, leading to ineffective pinning.
- **Dynamic Pinning without Security**: Retrieving pins dynamically over insecure channels without proper validation, making it easy for attackers to supply malicious pins.
- **Weak Validation Logic**: Custom pinning implementations that do not correctly validate the certificate chain or public key. For example, accepting any certificate that chains to a trusted root CA instead of a specific certificate or public key.
- **Lack of Backup Pins**: Not including backup pins to prevent connectivity issues if the primary pin is no longer valid.

## Mitigations

- **Prefer Platform-provided Solutions**: Use platform-provided mechanisms like Android's Network Security Configuration (NSC) or iOS's App Transport Security (ATS) to enforce pinning.
- **Use Trusted Pinning Libraries**: Refrain from writing custom pinning logic; instead, rely on established and well-maintained libraries and frameworks (e.g., TrustKit, OkHttp's `CertificatePinner`) and ensure they are correctly configured according to best practices.
- **Secure Dynamic Pinning**: If dynamic pinning is necessary, retrieve pins over secure channels and validate them thoroughly before use.
- **Pin to Public Keys Instead of Certificates**: Pin to the certificate's public key rather than the whole certificate to avoid issues regarding expiration and renewals.
- **Consistent Enforcement**: Apply pinning uniformly for all connections to servers that you control.
- **Regularly Update Pins**: Keep the pinned certificates or public keys up to date with the server's current configuration and have a process for updating the app when changes occur.
- **Implement Backup Pins**: Include backup pins (hashes of additional trusted public keys) to prevent connectivity issues if the primary key changes.
