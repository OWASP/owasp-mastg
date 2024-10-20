---
title: User Identification and Tracking  
id: MASWE-0110
alias: user-identification-and-tracking
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: 
  masvs-v2: [MASVS-PRIVACY-2]
  cwe: [359]
status: new
---

## Overview

Without proper controls, the collection of unique identifiers—such as device IDs, IP addresses, or behavioral patterns—can enable the identification and tracking of users across different services and over time. This lack of privacy safeguards can result in unauthorized profiling, targeted advertising without consent, and potential legal issues.

The absence of unlinkability techniques like data abstraction, anonymization, and pseudonymization contributes to this risk. Additionally, failing to establish technical barriers when utilizing complex "fingerprint"-like data points can lead to unintended cross-usage of data, compromising user privacy.


## Modes of Introduction

This risk can be introduced in various scenarios, including:

- **Unnecessary collection of identifiers**: Identifiers such as device IDs, IP addresses, behavioral patterns can be used to identify and track users.
- **Lack of Anonymization or Pseudonymization Measures**: Failure to implement anonymization or pseudonymization measures to strip data of direct identifiers such as user ID or name prior to server-side collection.


## Impact

- **Violation of User Privacy**: Users may not be aware that their personal information is being collected for tracking purposes, leading to privacy infringement.
- **Compliance and Legal Risks**: Breach of data protection laws and regulations (like GDPR), resulting in legal consequences and fines.

## Mitigations

- **Use Anonymisation and Pseudonymisation**: Ensure techniques like anonymisation and pseudonymisation are implemented to prevent user identification.
- **Avoid Unique Identifiers**: Avoid using identifiers that are unique, or probabilistically unique. Instead, opt for identifiers that can be reset.
