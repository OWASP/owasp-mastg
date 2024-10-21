---
title: Inadequate Privacy Policy
id: MASWE-0111
alias: privacy-policy
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: [MASVS-STORAGE-12]
  masvs-v2: [MASVS-PRIVACY-3]
  cwe: [359]
refs:
- https://support.google.com/googleplay/android-developer/answer/9859455#privacy_policy
- https://developer.apple.com/app-store/app-privacy-details/#privacy-links
- https://developer.apple.com/app-store/review/guidelines/#5.1.1
status: new
---

## Overview

Mobile apps must provide users with a clear and comprehensive statement regarding how their data is collected, processed, shared, and protected. Privacy policies should be easily accessible, tailored specifically to the app in question, and written in a way that users can easily understand. Without a robust privacy policy, users are unable to make informed decisions about their data, and may be unaware of how their information is being used or shared.

A privacy policy that is incomplete, vague, or does not match the app's behavior can mislead users and lead to a lack of transparency, resulting in potential privacy violations and legal repercussions for developers.

## Modes of Introduction

- **Unclear or Absent Privacy Policy**: Not providing a privacy policy, or having one that is not easily accessible or clear to the user, or that doesn't specifically address the data practices of that particular app, instead being a generic document that covers multiple services.  
- **Discrepancies in Policy vs Behavior**: Differences between the privacy policy and the app's actual behavior.

## Impact

- **Violation of User Privacy**: Users may unknowingly provide data without understanding how it will be used, exposing them to privacy risks, such as data sharing with third parties, profiling, or targeted advertising without explicit consent.
- **Loss of User Trust**: Users are more likely to lose trust in an app that lacks transparency, which may lead to negative reviews, decreased user engagement, and reduced retention rates.
- **Legal and Compliance Issues**: Failure to provide an adequate privacy policy can result in non-compliance with privacy laws and regulations, such as GDPR or CCPA, potentially leading to fines, legal action, or removal from app stores.

## Mitigations

- **Provide a Clear Privacy Policy**: Make sure a comprehensive and understandable privacy policy is readily accessible to users. Tailor it to the specific data practices of your app and write it in clear, understandable language as stated in Article 12 of the GDPR.  
- **Ensure Consistency in Privacy vs Behavior**: Keep your data collection practices documented and up to date in privacy policies, privacy labels, and app store listings. Ensure that these documents match the app's actual behavior to avoid discrepancies that could mislead users or violate platform policies.  
- **Regularly Review and Update Privacy Policy**: Regularly review and update the privacy policy to reflect any changes in data collection practices, new features, or modifications to existing features that may impact how user data is handled.
