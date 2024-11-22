---
title: Insecure Non-HTTP Traffic
id: MASWE-0048
alias: insecure-non-http
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-NETWORK-1]
  masvs-v2: [MASVS-NETWORK-1]

draft:
  description: e.g. FTP, SMTP, etc.
  topics: null
status: draft
note: move to cleartext traffic as a mode/test and repurpose for https://developer.android.com/privacy-and-security/risks/insecure-machine-to-machine ? 
---

## Overview

Applications that transmit data using insecure non-HTTP protocols such as FTP, SMTP, or unencrypted TCP sockets are vulnerable to interception, eavesdropping, and manipulation by attackers. These protocols lack built-in encryption and authentication mechanisms, allowing sensitive information to be exposed during transmission. Without proper security measures, data sent over these channels can be easily accessed by unauthorized parties.

## Impact

- **Data Interception**: Attackers can capture and read unencrypted data transmitted over insecure protocols.
- **Data Manipulation**: Unauthorized parties may alter data in transit, leading to corruption or injection of malicious content.
- **Unauthorized Access**: Credentials or authentication tokens sent over insecure channels can be intercepted, enabling attackers to gain unauthorized access to systems or user accounts.
- **Privacy Breach**: Exposure of personal or confidential information can lead to privacy violations and legal repercussions.
- **Regulatory Non-Compliance**: Transmitting sensitive data without adequate protection may violate industry regulations and standards.

## Modes of Introduction

- **Use of Insecure Protocols**: Employing protocols like FTP, SMTP without TLS, or unsecured TCP sockets for data transmission.
- **Legacy Systems Integration**: Integrating with older systems or services that only support insecure protocols.
- **Custom Protocol Implementations**: Developing custom communication protocols without proper encryption and authentication.
- **Misconfigured Secure Protocols**: Incorrectly configuring protocols intended to be secure, resulting in unencrypted communication (e.g., failing to enable TLS on SMTP servers).
- **Third-Party Libraries**: Using third-party libraries or SDKs that default to insecure communication methods.

## Mitigations

- **Use Secure Protocols**: Replace insecure protocols with secure alternatives that provide encryption and authentication, such as FTPS, SFTP, SMTPS, or HTTPS.
- **Implement Encryption**: If using custom protocols, ensure that data is encrypted in transit using standard encryption algorithms like TLS.
- **Enable Protocol Security Features**: Configure protocols to use their built-in security features, such as enabling TLS for SMTP or FTP.
- **Update Legacy Systems**: Work with legacy system providers to upgrade or replace systems to support secure communication protocols.
- **Validate Third-Party Components**: Ensure that all third-party libraries and SDKs are configured to use secure communication methods by default.
