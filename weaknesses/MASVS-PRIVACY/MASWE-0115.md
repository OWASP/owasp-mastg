---
title: Inadequate or Ambiguous User Consent Mechanisms
id: MASWE-0115
alias: ambiguous-consent-mechanisms
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: []
  masvs-v2: [MASVS-PRIVACY-4]
  cwe: [359]
refs:
- https://developer.apple.com/design/human-interface-guidelines/privacy#Requesting-permission
- https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/requesting_access_to_protected_resources
- https://developer.android.com/training/permissions/requesting#explain
status: new
---

## Overview

According to various international privacy regulations, such as the [EU's GDPR](https://gdpr-info.eu/art-7-gdpr/), [California's CCPA](https://cppa.ca.gov/regulations/pdf/cppa_act.pdf), [Brazil's LGPD](https://lgpd-brazil.info/chapter_02/article_08), and [Canada's PIPEDA](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/p_principle/principles/p_consent/), user consent must be explicit, informed, and obtained prior to any data processing. Users must be made fully aware of the purposes of the data collection, as well as the potential consequences of providing consent. In addition, consent should be an active choice, specific to the data being processed, and not bundled with other service agreements or presented in a vague or coercive manner.

Mobile apps that fail to follow these principles often result in users unknowingly consenting to data collection or processing that could pose significant risks to their fundamental rights and freedoms. For example, apps may use vague or non-negotiable consent requests, pressuring users to provide consent without fully understanding the implications.

In addition, users must be able to easily withdraw their consent at any time and should be clearly informed of how to do so, including the potential impact on the functionality of the app. Developers must maintain a record of user consent and ensure that consent requests are clear, separate from other terms, and legally valid, and avoid practices that obscure the full scope of data processing.

## Modes of Introduction

- **Failure to Prompt for Consent Changes**: Failing to prompt the user for consent when data collection practices change or when additional data is collected beyond what was originally specified.
- **Ambiguous Consent Mechanisms**: Consent is bundled with terms of service, often covering future use cases without notifying the user again. In some cases, consent is implied if the user doesn't explicitly deny access, leading to data collection without clear approval.

## Impact

- **Violation of User Privacy**: When ambiguous consent mechanisms are used, user privacy is severely compromised as users may unknowingly give up control over their data. This exposes them to the risk of their information being used without clear or informed consent for purposes they may find objectionable or harmful, such as targeted advertising, profiling, discrimination or even identity theft.
- **Loss of User Trust**: Users may lose trust in the app and abandon it, share negative reviews, or discourage others from using it, leading to reputational damage and potential loss of business.
- **Legal and Compliance Issues**: Non-compliance with laws and platform requirements can result in legal consequences, fines, or removal from app stores.

## Mitigations

- **Prompt for Consent on Changes**: Establish mechanisms for prompting users for consent if data collection practices change or if additional data is being collected, ensuring transparency when app functionality evolves.
- **Obtain Clear and Explicit User Consent for Immediate Actions**: Before accessing sensitive resources like sensors or local data (e.g., camera, location), always request explicit permission from the user. Clearly explain why the permission is needed, using mechanisms like [purpose strings](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/requesting_access_to_protected_resources) on iOS or [similar prompts](https://developer.android.com/training/permissions/requesting#explain) on Android, to ensure users understand the immediate use of their data.
- **Ensure Informed and Transparent Consent**: Provide users with clear, specific information about what data will be collected, how it will be used, and the potential impact. Consent should not be hidden in terms of service or bundled for future uses. Users must confirm consent separately for each purpose, especially when permissions extend beyond the initial request.
