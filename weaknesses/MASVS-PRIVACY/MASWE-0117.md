---
title: Inadequate Permission Management
id: MASWE-0117
alias: inadequate-permission-management
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: []
  masvs-v2: [MASVS-PRIVACY-1]
  cwe: [250]
refs:
- https://developer.apple.com/design/human-interface-guidelines/privacy#Requesting-permission
- https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/requesting_access_to_protected_resources
- https://developer.android.com/training/permissions/requesting#explain
- https://support.google.com/googleplay/android-developer/answer/9888170?hl=en
- https://developer.android.com/privacy-and-security/minimize-permission-requests
- https://developer.android.com/training/permissions/requesting
- https://developer.android.com/training/permissions/requesting#remove-access
- https://developer.android.com/training/permissions/usage-notes
- https://arxiv.org/pdf/1905.02713
- https://arxiv.org/pdf/2203.10583
- 

status: new
---

## Overview

Inadequate permission management poses significant risks to user privacy and security in mobile apps. Permissions control access to sensitive device features, such as the camera, microphone, location, and storage, which are essential for app functionality. However, improper management, such as requesting excessive or unnecessary permissions, can lead to privacy violations, unauthorized data access, and erosion of user trust. For example, some apps retain access to sensitive resources long after they are no longer needed (even when platforms like Android 13 offer mechanisms to revoke unused permissions). Developers face the challenge of balancing functionality with privacy, as revoking permissions can disrupt app usability, forcing users to choose between privacy and functionality.

Some apps, especially those that come pre-installed on devices, are often granted excessive privileges without needing explicit consent. Also, some regular apps may request permissions that are not necessary for their core functionality or request broader access than needed. For example, granting access to the camera may also grant access to the photo gallery, reducing user control. Privacy-friendly alternatives (e.g., coarse location or image picker) are often ignored.

Third-party libraries (SDKs) further complicate permission management by inheriting app permissions. The third-party services behind those libraries may continue to access data collected over the network even after permissions are revoked or the app is deleted. Users typically lack visibility and control over this data retention, which can then be used for marketing, profiling, or other purposes without the user's explicit consent or control.

## Modes of Introduction

- **Lack of Proactive Permission Revocation**: Not automatically revoking app permissions that are no longer necessary, resulting in unnecessary data access over time.  
- **Requesting Excessive Permissions**: Apps requesting more permissions than necessary for core functionality, often resulting in excessive data collection beyond what is required for the app to operate.
- **Lack of Use of Privacy-Friendly Alternatives**: Failing to use privacy-friendly alternatives to permissions that are less intrusive and provide users with more control over their data. For example, using coarse location instead of fine location, or using an image picker instead of requesting access to the camera and photo gallery.

## Impact

- **Violation of User Privacy**: Users may have their personal data accessed unnecessarily leading to potential misuse of personal data, identity theft or surveillance.  
- **Loss of User Trust**: Users may lose trust in an app if it requests unnecessary permissions or does not allow them to revoke permissions that are no longer relevant. This can lead to negative reviews, lower user engagement, and reduced retention.
- **Legal and Compliance Issues**: Apps that improperly manage permissions may face non-compliance with privacy regulations like GDPR or CCPA, which require data minimization and appropriate user control over data access, resulting in potential fines, legal action, or removal from app stores.
- **Malicious Abuse:** Harmful apps can misuse permissions from privileged apps to record, track, or steal data without user consent.
- **Security Breaches:** Once the collected sensitive data otherwise protected by permissions leaves the app, if it's poorly protected on the remote endpoints, it can be vulnerable to cyberattacks.

## Mitigations

- **Enable Proactive Permission Revocation**: Automatically revoke permissions that are no longer necessary to minimize unnecessary data access over time. Ensure that users can manually revoke permissions at any time through a clear and accessible interface.
- **Prefer Privacy-Friendly Alternatives**: Use privacy-friendly alternatives to permissions that are less intrusive and provide users with more control over their data. For example, use coarse location instead of fine location, or use an image picker instead of requesting access to the camera and photo gallery.
- **Limit Permissions to Essential Needs**: Ensure apps only request permissions necessary for core functionality, avoiding the collection of unnecessary data and adhering to the principle of data minimization.
- **Implement Just-in-Time Permission Requests**: Request permissions only when they are needed, providing clear explanations for why each permission is required. This approach helps build user trust and ensures users understand the implications of granting access to their data.
- **User Education on Permissions**: Educate users about why specific permissions are needed and how they can manage these permissions. Providing transparency builds user trust and ensures users understand the importance and relevance of each permission.
