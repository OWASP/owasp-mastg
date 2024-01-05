---
mappings:
  - cwe:
    - id: 200
      title: Exposure of Sensitive Information to an Unauthorized Actor
    - id: 201
      title: Insertion of Sensitive Information Into Sent Data
    - id: 359
      title: Exposure of Private Personal Information to an Unauthorized Actor
    - id: 497
      title: Exposure of Sensitive System Information to an Unauthorized Control Sphere

title: Sensitive Data in Network Traffic
platform: android
profiles: ["P"]
profiles_rationale: This risk is part of the MAS privacy profile because most of apps will insert sensitive data into network traffic, but, as long as the communication is properly encrypted this is not a security risk.
---

## Overview

Mobile apps may send [sensitive data](MASTG-THEORY-0023.md "Sensitive Data") over the [network](MASTG-THEORY-0035.md "Network Communication"). This may include sensitive user data, such as passwords, credit card numbers, or other personally identifiable information (PII), as well as sensitive system data, such as cryptographic keys, session tokens, or other sensitive information.

Sending sensitive data over the network is a common practice, but it should be avoided whenever possible. It is essential to follow the principle of data minimization, e.g. by only sending the data that is absolutely necessary and of course, it should be done securely, e.g. using TLS.

## Modes of Introduction

This can typically occur in different ways:

- **Using high-level platform-provided APIs**: for example via `HttpsURLConnection` on Android or `URLSession` on iOS.
- **Using low-level platform-provided APIs**: for example via `SSLSocket` on Android or `Network` on iOS.
- **Using third-party libraries**: for example via `Retrofit` or `Volley`.

Sensitive data sent over the network will be available for an attacker performing a Man-in-the-Middle (MitM) attack, unless it is additionally encrypted using end-to-end encryption.

## Impact

Loss of confidentiality: Sentitiva data within network traffic is at risk of being exposed to an attacker who may be able to intercept it. This may lead to further attacks, such as identity theft, or compromise of the application's backend.

Loss of privacy: Sentitiva data within network traffic is at risk of being exposed to a third party, which could use it for malicious purposes, such as tracking the user.

## Mitigations

- Fully identify all data that should be considered sensitive.
- [Data minimization](mitigations/MAS-MITIGATION-0003): Only send the data that is absolutely necessary for the app functionality.
- [Data anonymization / pseudonymization](mitigations/MAS-MITIGATION-0004): before sending it over the network, ensure that the data is anonymized or pseudonymized.
- [Secure Network Communication](mitigations/MAS-MITIGATION-0005): Use secure protocols, such as TLS, to send sensitive data over the network.
- [End-to-end encryption](mitigations/MAS-MITIGATION-0006): encrypt sensitive data before sending it over the network.
