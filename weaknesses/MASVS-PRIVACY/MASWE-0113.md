---
title: Ambiguous consent mechanisms
id: MASWE-01013
alias: ambiguous-consent-mechanisms
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: [MASVS-STORAGE-12]
  masvs-v2: [MASVS-PRIVACY-3, MASVS-PRIVACY-4]
  cwe: [359]
status: new
---

## Overview
Consent should be freely given, specific, informed and unambiguous.

The risk here is to bundle consent with the terms of services or the processing of data outside of the original consent scope. 


## Modes of Introduction

This risk can be introduced in various scenarios, including:

- Consent is bundled with the terms of services. For example, the consent language says ‘by using this service, you agree to provide your data for research purposes.’
- Consent covers future use cases. For example, consent to pair one device automatically applies to new devices in the future and no additional consent is obtained. 



## Impact

The impact of exposing sensitive data in network traffic includes:

- **Violation of User Privacy**: Users may not be aware that their personal information is being used for secondary purpose or continuous access, leading to privacy infringement.
- **Compliance and Legal Risks**: Breach of data protection laws and regulations (like GDPR), resulting in legal consequences and fines.
- **Loss of User Trust**: Users losing trust in the application, leading to reputational damage and potential loss of business.

## Mitigations

To mitigate this risk, consider the following strategies:

- The consent notice should include all essential notice components such as scope, purpose, and impact of processing.
- Ensure consent is required when the permission is beyond the original scope. 

