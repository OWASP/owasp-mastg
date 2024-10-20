---
title: Lack of Transparency about Data Collection and Usage
id: MASWE-0111
alias: transparency-data-collection-usage
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: [MASVS-STORAGE-12]
  masvs-v2: [MASVS-PRIVACY-3]
  cwe: [359]
status: new
---

## Overview

Transparency about data collection and usage refers to the user's right to know what data is being collected and how it is being used. The lack of transparency can result in data being collected and shared without user awareness or consent.

In addition to standard privacy policies required by laws and regulations, both Apple and Google have introduced new privacy labeling systems to enhance user understanding of data practices. Apple's App Store introduced Privacy Nutrition Labels in 2020, and Google Play launched the Data Safety Section in 2021. These labels are designed to help users easily comprehend how their data is collected, handled, and shared. As these are new requirements on both platforms, it is crucial for developers to provide accurate and up-to-date information in these labels to reassure users and prevent misuse of data.

## Modes of Introduction

- **Unclear or Absent Privacy Policy**: Not providing a privacy policy, or having one that is not easily accessible or clear to the user, or that doesn't specifically address the data practices of that particular app, instead being a generic document that covers multiple services.
- **Undeclared Data Collection and Purpose**: Failing to declare what data is being collected and for what purposes, leaving users unaware of how their information is used.
- **Discrepancies in Declarations vs Behavior**: Differences between privacy label declarations (such as Apple's Privacy Nutrition Labels or Google's Data Safety Section), the privacy policy, and the app's actual behavior.

## Impact

- **Violation of User Privacy**: If users are unaware of how their data is used, they cannot effectively assess the risks involved. This could lead to their data being used for purposes they find objectionable or harmful, such as targeted advertising, discrimination, or identity theft.
- **Loss of User Trust**: Users may lose trust in the app and abandon it, share negative reviews, or discourage others from using it, leading to reputational damage and potential loss of business.
- **Legal and Compliance Issues**: Non-compliance with laws and platform requirements can result in legal consequences, fines, or removal from app stores.

## Mitigations

- **Maintain Accurate Privacy Labels**: Comply with Apple's Privacy Nutrition Labels and Google's Data Safety Section requirements by providing accurate and transparent information about your data practices, including data collection and sharing with third parties.
- **Ensure Consistency in Declarations vs Behavior**: Keep your data collection practices documented and up to date in privacy policies, privacy labels, and app store listings. Ensure that these documents match the app's actual behavior to avoid discrepancies that could mislead users or violate platform policies.
- **Provide a Clear Privacy Policy**: Make sure a comprehensive and understandable privacy policy is readily accessible to users. Tailor it to the specific data practices of your app and write it in clear, understandable language as stated in Article 12 of the GDPR.
