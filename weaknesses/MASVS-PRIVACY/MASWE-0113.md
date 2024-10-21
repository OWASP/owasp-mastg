---
title: Lack of Proper Data Management Controls
id: MASWE-0113
alias: data-management-controls
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: []
  masvs-v2: [MASVS-PRIVACY-4]
  cwe: [359]
refs:
- https://developer.apple.com/app-store/app-privacy-details/#privacy-links
status: new
---

## Overview

When mobile apps do not provide users with mechanisms specifically designed to manage their personal data, users are left without adequate options to manage their information. This limits users' rights over their own data, leading to privacy concerns, increased severity of potential data breaches, and potential non-compliance with privacy regulations.

These mechanisms typically include the ability for users to delete, export, modify, or opt out of data collection directly within the app interface. For example, some apps provide data management features within the settings menu, while others provide a link to an external website where users can manage their data.

## Modes of Introduction

- **Lack of Proper Data Management Settings**: Failing to provide users with the ability to delete, export, modify, or opt out of data collection, resulting in users having limited or no control over their personal data.

## Impact

- **Violation of User Rights**: Users may be unable to exercise their rights to manage their personal data, such as deleting or exporting their information, leading to a lack of control and increased privacy risks.  
- **Non-Compliance with Privacy Regulations**: Non-compliance with regulations like GDPR and CCPA, which require providing users with data management capabilities, can result in fines, legal action, and other consequences.  
- **Loss of User Trust**: Users may lose trust in an app that does not allow them to manage their personal data, which can lead to negative reviews, decreased user engagement, and reduced retention.

## Mitigations

- **Implement Data Management Mechanisms**: Ensure that mechanisms are in place for users to delete, export, or modify their data. Provide granular controls for specific aspects of data collection and sharing (e.g., location services, contacts, media access).  
- **Regularly Update Data Management Features**: Regularly review and update data management features to ensure compliance with evolving regulations and user expectations. This helps maintain transparency and user trust.  
- **User-Friendly Data Management Interface**: Create a user-friendly interface for data management controls, ensuring that users can easily navigate and exercise their rights over their personal data without friction.
