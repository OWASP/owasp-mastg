---
title: Sensitive Data in Network Traffic
alias: sensitive-data-in-network-traffic
platform: ["android", "ios"]
profiles: ["P"]
mappings:
- masvs-v1: [MSTG-NETWORK-1]
- masvs-v2: [MASVS-PRIVACY-1]
- cwe: [359]
---

## Overview

Sensitive data in network traffic refers to the transmission of personal or confidential information over the network in a manner that could be intercepted and accessed by unauthorized parties. While the data may be sent using secure protocols such as HTTPS, the primary concern is the appropriateness and necessity of the data being shared or collected.

The risk is not in the security of the transmission method, but in the privacy implications of the data being transmitted. This could include personal user information, location data, usage patterns, or any other information that could compromise user privacy.

## Modes of Introduction

This risk can be introduced in various scenarios, including:

- Over-collection of user data beyond the app's functional requirements.
- Transmission of detailed user location or behavior analytics without proper anonymization.
- Sharing sensitive information with third-party services (e.g., analytics, advertising networks) without user consent.
- Unnecessary collection of identifiers like IMEI, email, or phone numbers.

## Impact

The impact of exposing sensitive data in network traffic includes:

- **Violation of User Privacy**: Users may not be aware that their personal information is being transmitted, leading to privacy infringement.
- **Compliance and Legal Risks**: Breach of data protection laws and regulations (like GDPR), resulting in legal consequences and fines.
- **Loss of User Trust**: Users losing trust in the application, leading to reputational damage and potential loss of business.

## Mitigations

To mitigate this risk, consider the following strategies:

- Minimize the collection of user data to what is strictly necessary for app functionality.
- Implement and strictly enforce data privacy policies, including user consent for data collection and sharing.
- Use anonymization techniques for user data that is transmitted for analytics or other secondary purposes.
- Regularly review and audit data transmitted over the network to ensure it aligns with privacy policies and user expectations.
- Provide clear user-facing privacy settings, allowing users to control what data is shared.
