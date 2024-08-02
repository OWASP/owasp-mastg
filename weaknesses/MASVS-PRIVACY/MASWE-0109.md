---
title: Secondary purpose of sensitive data use
id: MASWE-0109
alias: sensitive-data-secondary-purpose
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: [MSTG-NETWORK-1]
  masvs-v2: [MASVS-PRIVACY-1, MASVS-PRIVACY-2, MASVS-PRIVACY-4]
  cwe: [359]
status: new
---

## Overview
Sensitive data might be used for secondary purposes or beyond the initial scope without notice or consent from users, while a user consent is obtained for the collection of such data for the initial purpose.

## Modes of Introduction

This risk can be introduced in various scenarios, including:

- Use of user data collected for secondary purpose without user consent or control.
- Continuous access to user data without user controls.


## Impact

The impact of exposing sensitive data in network traffic includes:

- **Violation of User Privacy**: Users may not be aware that their personal information is being used for secondary purpose or continuous access, leading to privacy infringement.
- **Compliance and Legal Risks**: Breach of data protection laws and regulations (like GDPR), resulting in legal consequences and fines.
- **Loss of User Trust**: Users losing trust in the application, leading to reputational damage and potential loss of business.

## Mitigations

To mitigate this risk, consider the following strategies:

- Implement and strictly enforce data privacy policies for purpose limitation.
- Audit data processing implementation to verify whether the data is used for secondary purposes.
