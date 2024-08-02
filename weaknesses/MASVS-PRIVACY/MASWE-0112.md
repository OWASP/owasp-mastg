---
title: User Data Control 
id: MASWE-0112
alias: user-data-control
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: [MSTG-STORAGE-12]
  masvs-v2: [MASVS-PRIVACY-4]
  cwe: [359]
status: new
---

## Overview

Offer users control over their data refers to giving the user the option of managing, deleting, modifying and revoking consent to their data. Including re prompting for consent when requesting more data than initially specified.

The risk here is the user not having control of their data once collected. To mitigate this risk, users should be provided the option to request deletion of collected data, revoke consent and allow users to modify privacy settings with granularity.


## Modes of Introduction

This risk can be introduced in various scenarios, including:

- Not providing the user with the option to delete, modify and opt out of data collection.
- Not providing privacy setting with granularity.
- Not prompting the user for consent if data collection has changed.



## Impact

The impact of exposing sensitive data in network traffic includes:

- **Violation of User Privacy**: Users may not be aware that their personal information is being used for secondary purpose or continuous access, leading to privacy infringement.
- **Compliance and Legal Risks**: Breach of data protection laws and regulations (like GDPR), resulting in legal consequences and fines.
- **Loss of User Trust**: Users losing trust in the application, leading to reputational damage and potential loss of business.

## Mitigations

To mitigate this risk, consider the following strategies:

- Ensure mechanisms are in place for users to delete all their data and modify privacy settings with granularity.
- Ensure mechanisms for prompting for consent if data collection has changed.
