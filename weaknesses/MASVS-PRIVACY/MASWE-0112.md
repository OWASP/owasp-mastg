---
title: Inadequate Data Collection Declarations
id: MASWE-0112
alias: data-collection-declarations
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: [MSTG-STORAGE-12]
  masvs-v2: [MASVS-PRIVACY-3]
  cwe: [359]
refs:
- https://support.apple.com/en-us/102188
- https://support.apple.com/kb/HT211970
- https://developer.apple.com/app-store/review/guidelines/#5.1.2
- https://developer.apple.com/app-store/app-privacy-details/#data-collection
- https://support.google.com/googleplay/android-developer/answer/10787469
status: new
---

## Overview

When a mobile app's stated data collection practices, such as those documented in Apple's [App Privacy Report](https://support.apple.com/en-us/102188) and [Privacy Nutrition Labels](https://support.apple.com/kb/HT211970), or Google's [Data Safety section](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en), are incomplete or inconsistent with the app's actual behavior, users are prevented from making informed decisions about their privacy, including understanding whether data will be linked to their identity, used for tracking, or shared with third parties.

These declarations must clearly outline what data is collected, how it is used, whether it is linked to the user's identity, and whether it is shared with third parties in accordance with the platform's policies.

**Note about third-party libraries (SDKs)**: Developers, as data controllers, are legally responsible for ensuring that third-party components process sensitive data lawfully, fairly, and transparently, as highlighted in the [ENISA study on GDPR compliance](https://www.enisa.europa.eu/sites/default/files/publications/WP2017%20O-2-2-4%20GDPR%20Mobile.pdf) (Section 2.2.7, _"Data transfers and processing by third parties"_). However, in some cases, it may be challenging for mobile app developers to be fully aware of what data these third-party SDKs actually collect.

## Modes of Introduction

- **Undeclared Data Collection and Purpose**: Failing to declare what data is being collected (e.g., location, contacts, identifiers) and for what purposes (e.g., analytics, personalization), leaving users unaware of how their information is used.  
- **Discrepancies in Declarations vs Behavior**: Differences between privacy label declarations (such as Apple's Privacy Nutrition Labels or Google's Data Safety Section) and the app's actual behavior, including undeclared data collection, sharing with third parties not mentioned in privacy labels, or using data for purposes not disclosed, which are against both Apple and Google guidelines.

## Impact

- **Violation of User Privacy**: Users may unknowingly share data without fully understanding its purpose, which can lead to unauthorized sharing, profiling, or targeted advertising.  
- **Loss of User Trust**: Inconsistent declarations can result in users losing trust in the app, leading to negative reviews, lower user engagement, and reduced retention.  
- **Legal and Compliance Issues**: Inaccurate or inconsistent data declarations may lead to non-compliance with regulations like GDPR or CCPA, resulting in potential fines, legal action, or removal from app stores.

## Mitigations

- **Maintain Accurate Privacy Labels**: Comply with Apple's Privacy Nutrition Labels and Google's Data Safety Section requirements by providing accurate and transparent information about your data practices, including data collection and sharing with third parties.  
- **Ensure Consistency in Declarations vs Behavior**: Keep your data collection practices documented and up to date in privacy policies, privacy labels, and app store listings. Ensure that these documents match the app's actual behavior to avoid discrepancies that could mislead users or violate platform policies.
