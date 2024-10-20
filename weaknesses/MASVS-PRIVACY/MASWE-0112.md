---
title: Lack of User Data Control
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

Lack of user data control refers to situations where users do not have the ability to manage, delete, modify, or revoke access to their personal data. Even after uninstalling apps, user data may still be retained on servers or shared with third parties (e.g., analytics or advertising platforms). This violates essential user data privacy rights, such as the GDPR's Intervenability Rights - the right to access (Article 15), rectify (Article 16), erasure or "right to be forgotten" (Article 17), restriction of processing (Article 18), and the right to object (Article 21).

## Modes of Introduction

- **Lack of Proper Data Management Settings**: Failing to provide users with the ability to delete, export, modify, or opt out of data collection.
- **Lack of Granular Privacy Settings**: Failing to provide privacy settings with sufficient granularity to allow users to control specific aspects of data collection and sharing, such as differentiating between location services, contacts, or media access.

## Impact

- **Compliance and Legal Risks**: Without the proper user data controls in place, users may be unable to exercise essential privacy data rights, such as the right to access, rectify, erase, restrict processing or the right to object, which leaves them vulnerable to data misuse, such as targeted advertising, identity theft, or fraud. This can result in violations of data protection laws and regulations (such as GDPR), which can result in legal consequences and fines.
- **Loss of User Trust**: When users perceive an app as mismanaging their data, it leads to reputational damage and a potential loss of business. Negative reviews in app stores can further deter new users, reducing adoption rates and revenue. Additionally, a lack of trust may lead to reduced engagement and erosion of brand loyalty, as users seek more privacy-conscious alternatives.

## Mitigations

- **Implement Data Management Mechanisms**: Ensure that mechanisms are in place for users to delete, export, or modify their data, and provide granular controls for specific aspects of data collection and sharing (e.g., location services, contacts, media access).
- **Offer Granular Privacy Settings**: Provide privacy settings with sufficient granularity, allowing users to control individual data collection categories (e.g., location, contacts) and manage their sharing preferences.
