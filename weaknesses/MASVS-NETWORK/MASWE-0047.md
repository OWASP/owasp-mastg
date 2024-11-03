---
title: Insecure Identity Pinning
id: MASWE-0047
alias: insecure-pinning
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-NETWORK-4]
  masvs-v2: [MASVS-NETWORK-2]

draft:
  description: e.g. via NSC/ATS, okhttp CertificatePinner, volley, trustkit, Cordova,
    AFNetworking SSLPinningMode
  topics:
  - NSC/ATS
  - net-frameworks e.g. okhttp CertificatePinner, volley, trustkit, Cordova, AFNetworking
    SSLPinningMode
  - Dynamic Pinning e.g. via the ssl-pinning-android library
  - Check for MITM resiliency, e.g. with trusted interceptor cert. consider "proxy
    unaware apps"
status: draft

---

## Overview

Certificate pinning is a security technique used to ensure that an app only trusts specific certificates or public keys when establishing secure connections. Insecure identity pinning occurs when the implementation of certificate or public key pinning is flawed or improperly configured. This weakness can leave the app vulnerable to Man-in-the-Middle (MITM) attacks and other security threats. Common issues include outdated pins, improper validation, accepting all certificates, or using insecure methods for dynamic pinning.

## Impact

- **Data Interception**: Sensitive data such as credentials, personal information, or financial details can be captured by unauthorized parties.
- **Data Manipulation**: Attackers can not only intercept but also manipulate data if pinning is not properly enforced.
- **Denial of Service**: Incorrect pinning may cause legitimate connections to fail, leading to service disruptions for users. For example, if a pinned certificate expires and is not updated, the app may be unable to establish secure connections.

## Modes of Introduction

- **Improper Configuration of Pinning Libraries**: Misconfiguring libraries like TrustKit, OkHttp's `CertificatePinner`, Volley, or AFNetworking's `SSLPinningMode`, leading to ineffective pinning.
- **Dynamic Pinning without Security**: Retrieving pins dynamically over insecure channels without proper validation, making it easy for attackers to supply malicious pins.
- **Pinning to Insecure Certificates**: Pinning to self-signed, expired, or untrusted certificates that can be exploited.
- **Partial or Inconsistent Pinning**: Only applying pinning to certain network requests or failing to enforce it consistently across the app.
- **Weak Validation Logic**: Custom pinning implementations that do not correctly validate the certificate chain or public key. For example, accepting any certificate that chains to a trusted root instead of a specific certificate or public key.
- **Lack of Backup Pins**: Not including backup pins to prevent connectivity issues if the primary pin is no longer valid.

## Mitigations

- **Prefer Platform-provided Solutions**: Use platform-provided mechanisms like Android's Network Security Configuration (NSC) or iOS's App Transport Security (ATS) to enforce pinning.
- **Use Trusted Pinning Libraries**: Refrain from writing custom pinning logic; instead, rely on established and well-maintained libraries and frameworks (e.g., TrustKit, OkHttp's `CertificatePinner`) and ensure they are correctly configured according to best practices.
- **Secure Dynamic Pinning**: If dynamic pinning is necessary, retrieve pins over secure channels and validate them thoroughly before use.
- **Pin to Public Keys Instead of Certificates**: Pin to the server's public keys rather than certificates to avoid issues with certificate expiration and renewals.
- **Consistent Enforcement**: Apply pinning uniformly to all relevant network connections within the app.
- **Regularly Update Pins**: Keep the pinned certificates or public keys up to date with the server's current configuration and have a process for updating the app when changes occur.
- **Implement Backup Pins**: Include backup pins (hashes of additional trusted public keys) to prevent connectivity issues if the primary key changes.
