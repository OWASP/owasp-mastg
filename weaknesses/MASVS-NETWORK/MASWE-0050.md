---
title: Cleartext Traffic
id: MASWE-0050
alias: cleartext-traffic
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-NETWORK-2]
  masvs-v2: [MASVS-NETWORK-1]
  cwe: [319]
  android:
    - https://developer.android.com/privacy-and-security/risks/cleartext-communications
refs:
- https://developer.apple.com/documentation/security/preventing-insecure-network-connections
- https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nsexceptiondomains
- https://developer.apple.com/documentation/network
- https://developer.apple.com/documentation/foundation/urlsession
- https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted
- https://developer.android.com/reference/javax/net/ssl/SSLSocket
- https://developer.android.com/reference/android/security/NetworkSecurityPolicy#isCleartextTrafficPermitted()
- https://developer.android.com/reference/java/net/Socket
- https://developer.android.com/reference/android/webkit/WebView
- https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection
- https://github.com/MicrosoftDocs/xamarin-docs/blob/live/docs/android/app-fundamentals/http-stack.md
- https://github.com/MicrosoftDocs/xamarin-docs/blob/live/docs/ios/app-fundamentals/ats.md

status: new
---

## Overview

When data is sent in cleartext—without encryption—it becomes accessible to attackers who can monitor network channels. Attackers can perform passive eavesdropping to intercept data or employ active Man-in-the-Middle (MITM) attacks to manipulate data, potentially altering app behavior or injecting malicious content.

This weakness is especially concerning when sensitive information—like passwords, credit card numbers, or personal details—is transmitted without encryption, putting user privacy and security at direct risk. Even when sensitive data isn't being transmitted, cleartext communication remains a vulnerability. Network attacks like ARP poisoning and DNS spoofing can allow attackers to intercept or redirect traffic, potentially disrupting app functionality or deceiving users by redirecting them to malicious sites that impersonate legitimate services.

If the connections were secured using encryption and proper authentication mechanisms, these attacks would be much harder to perform because the attacker would need to bypass encryption and certificate validation. Secure network protocols not only provide confidentiality but also ensure data integrity and authenticity through encryption and certificate validation, preventing attackers from altering data.

## Impact

- **Data Interception**: Attackers can capture and read sensitive information transmitted over the network.
- **Data Manipulation**: Attackers might alter data in transit, causing corruption or injecting malicious content.
- **Unauthorized Access**: Attackers may intercept session tokens sent over cleartext channels, enabling them to impersonate users and gain unauthorized access to user accounts or systems.
- **Privacy Breach**: Personal and confidential user information could be exposed, violating privacy regulations.
- **Regulatory Compliance Violations**: Exposing sensitive data may lead to non-compliance with laws like GDPR or HIPAA, resulting in legal penalties.
- **Reputation Damage**: Security breaches can erode user trust and harm the organization's reputation.

## Modes of Introduction

- **Cleartext Traffic Allowed Globally in Configurations:** Global configuration settings allow cleartext traffic, making all network communication insecure.
- **Per-Domain Exceptions for Cleartext Traffic:** Specific domains are allowed to use cleartext traffic, bypassing the secure communication requirements.
- **Usage of Insecure Protocols:** Using insecure protocols such as HTTP or FTP which do not encrypt data in transit.
- **Low-Level API Usage:** Use of low-level networking APIs that do not enforce encryption can inadvertently lead to the transmission of unprotected data.
- **Cross-Platform Framework Misconfiguration:** Improper settings in cross-platform frameworks may allow cleartext traffic for both Android and iOS versions of an app.

## Mitigations

- **Use Secure Protocols:** Always use secure protocols like HTTPS, which employs TLS for encryption, for all communication channels. Ensure these protocols are used consistently throughout the app.
- **Explicitly Disable Cleartext Traffic:** Never allow cleartext traffic globally in the app configuration. Ensure that cleartext traffic is explicitly disabled using security settings like the Network Security Configuration on Android and App Transport Security (ATS) on iOS. Prefer per-domain exceptions over global settings but use them carefully and only when there is no other option.
- **Use Per-Domain Exceptions Sparingly:** If cleartext traffic is absolutely necessary for specific domains—for example, they do not handle sensitive data and data manipulation is not considered a risk—add exceptions carefully. Ensure these domains are trusted and essential for the app's functionality, and conduct a thorough risk assessment before including them.
- **Prefer Server Fixes**: Whenever possible, work with the server team to enable secure communication. Instead of adding network security exceptions to the mobile app, such as allowing cleartext traffic or lowering the minimum TLS version, update server configurations to support HTTPS with valid certificates and modern TLS protocols.
- **High-Level Network APIs:** Use high-level networking APIs that automatically handle encryption, certificate validation, and errors, such as `HttpsURLConnection` on Android or `URLSession` on iOS. Avoid using low-level networking APIs or custom network stacks that bypass the platform-provided network security features.
- **Use Secure Cross-Platform Frameworks:** Ensure that cross-platform frameworks—such as React Native, Flutter, or Xamarin—are configured to enforce secure communication by default and do not allow cleartext traffic. Review the framework's documentation and adjust network security settings to align with best practices.
- **Use Secure Third-Party Components**: Verify that any third-party libraries and SDKs used in the app enforce secure communication protocols, especially if they handle sensitive data or use low-level networking APIs. Ensure that these components are regularly updated to address any vulnerabilities.
- **Implement Certificate Pinning**: Use certificate pinning with servers you control as an additional layer of security to prevent MITM attacks. Ensure proper implementation to handle certificate updates smoothly, and be cautious to avoid connectivity issues if certificates change. Avoid pinning certificates for third-party services unless you have control over their certificate management.
