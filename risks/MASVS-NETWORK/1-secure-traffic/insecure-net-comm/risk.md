---
title: Insecure Network Communication
platform: ["android", "ios"]
profiles: ["L1", "L2"]
mappings:
- masvs-v1: [MSTG-NETWORK-1]
- masvs-v2: [MASVS-NETWORK-1]
- cwe: [319, 311]
- android: https://developer.android.com/privacy-and-security/risks/cleartext
---

## Overview

Insecure network communication consists of sending sensitive data over the network using insecure protocols, such as HTTP, or using secure protocols in an insecure way, such as disabling certificate validation. The result is that the data is sent in cleartext or plaintext, i.e. not encrypted.

Anyone monitoring the network traffic can easily capture and intercept it. If the app handles sensitive data or functionality this represents a serious risk.

## Modes of Introduction

This can typically occur in different ways:

- Network APIs incorrectly configured or used
    - High-level platform-provided APIs are configured securely by default, but may be used insecurely by the developer.
    - Low-level platform-provided APIs do not always honor platform-provided app network configurations.
    - Third-party libraries may not be configured securely by default.
- Insecure App Network Configuration.
- Having unprotected open ports.
- TLS errors ignored in the code.
- Allowing mixed content (HTTP and HTTPS) in the app.
- Using insecure handlers such as `http://` or `ws://`.

## Impact

Insecure network traffic can be easily captured and intercepted. This may lead to:

- **Loss of confidentiality**: exposure of sensitive data which can lead to further attacks, such as identity theft, or financial loss. For example, an attacker could intercept a credit card number and use it to make fraudulent purchases or use the user's credentials to access their account.
- **Loss of integrity**: manipulation of data in transit to influence the app's behavior. For example, an attacker could modify the app's response to a request to change the user's password, so that the new password is set to a value known to the attacker.

## Mitigations

Ensure that the app uses secure network communication, by following these guidelines:

- Use secure network APIs ans prefer high-level platform-provided APIs when possible.
- Use secure network configurations and don't deviate from the default configurations unless strictly necessary.
- Use secure network handlers.
- Use secure and trusted third-party libraries.
- Ensure the remote endpoint offers secure TLS configurations.
