---
title: Prevention of user identification and tracking  
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
Preventing identification of users is concerned with the risk of collecting data in a way that leads to user identification and tracking. The risk of user identification and tracking should be mitigated by ensuring use of unlinkability techniques such as data abstraction, anonymization and pseudonymization.

Technical barriers need to be established when utilizing complex ‘finger-print’ like data points for specific purposes to prevent cross-usage and ensure each data stream serves its intended function without compromising user privacy.


## Modes of Introduction

This risk can be introduced in various scenarios, including:

- Unnecessary collection of identifiers like device IDs, IP addresses, behavioral patterns that can lead to user identification and tracking.
- No anonymization and pseudonymisation measures to strip data of any direct identifiers such as user ID or name before server side collection.
- Reusing signals collected for a specific purpose for other features (e.g fingerprinting for fraud detection).


## Impact

The impact of user identification:

- **Violation of User Privacy**: Users may not be aware that their personal information is being collected for tracking purposes, leading to privacy infringement.
- **Compliance and Legal Risks**: Breach of data protection laws and regulations (like GDPR), resulting in legal consequences and fines.
- **Read Application Data**: If an app collects and exposes user data without proper anonymization, attackers could access and expose this data by reading the application's data storage. This could include sensitive information like names, addresses, financial details, and even health records.

## Mitigations

To mitigate this risk, consider the following strategies:

- Ensure techniques like anonymisation and pseudonymisation are implemented to prevent user identification.
- Avoid using identifiers that are unique, or probabilistically unique. Instead, opt for identifiers that can be reset.
