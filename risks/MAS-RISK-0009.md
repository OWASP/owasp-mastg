---
mappings:
  - cwe:
      - id: 311
        title: Missing Encryption of Sensitive Data
      - id: 319
        title: Cleartext Transmission of Sensitive Information
  - owasp-masvs: [MASVS-NETWORK-1]
  - owasp-masvs-v1: [MSTG-NETWORK-1]
title: Cleartext Network Communication
platform: android
profiles: ["L1", "L2"]
---

## Overview

Insecure network communication consists of sending sensitive data over the network using insecure protocols, such as HTTP, or using secure protocols in an insecure way, such as disabling certificate validation. The result is that the data is sent in cleartext or plaintext, i.e. not encrypted.

Anyone monitoring the network traffic can easily capture and intercept it. If the app handles sensitive data or functionality this represents a serious risk.

## Modes of Introduction

This can typically occur in different ways:

- Network API Incorrectly Configured or Used
    - **high-level platform-provided APIs**: These APIs (for example `HttpsURLConnection` on Android or `URLSession` on iOS) are configured securely by default, but may be used insecurely by the developer.
    - **low-level platform-provided APIs**: Security configurations such as ATS don't apply to these APIs (for example `SSLSocket` on Android or `Network` on iOS).
    - **third-party libraries**: third-party libraries may not be configured securely by default.
- Insecure App Network Configuration such as Network Security Configuration (NSC) on Android or App Transport Security (ATS) on iOS.
- Having unprotected Open Ports
- TLS errors ignored in the code (e.g. via `onReceivedSslError` on Android)
- Allowing mixed content (HTTP and HTTPS) in the app
- Using insecure handlers such as http:// or ws://

## Impact

Insecure network traffic can be easily captured and intercepted. This may lead to:

- Loss of confidentiality: exposure of sensitive data which can lead to further attacks, such as identity theft, or financial loss. For example, an attacker could intercept a credit card number and use it to make fraudulent purchases or use the user's credentials to access their account.
- Loss of integrity: manipulation of data in transit to influence the app's behavior. For example, an attacker could modify the app's response to a request to change the user's password, so that the new password is set to a value known to the attacker.

## Mitigations

- [Secure Network Communication](mitigations/MAS-MITIGATION-0005): Use secure protocols, such as TLS, to send sensitive data over the network.
