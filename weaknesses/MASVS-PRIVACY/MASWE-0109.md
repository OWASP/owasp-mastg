---
title: Lack of Anonymization or Pseudonymisation Measures
id: MASWE-0109
alias: anonymization-pseudonymization-measures
platform: ["android", "ios"]
profiles: ["P"]
mappings:
  masvs-v1: []
  masvs-v2: [MASVS-PRIVACY-2]
  cwe: [359]
refs:
- https://cloud.google.com/sensitive-data-protection/docs/classification-redaction
- https://gdpr-info.eu/recitals/no-26/
- https://gdpr-info.eu/recitals/no-28/
- https://gdpr-info.eu/art-4-gdpr/
- https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp216_en.pdf
- https://www.statista.com/topics/9460/app-tracking-and-mobile-privacy/
status: new
---

## Overview

The absence of unlinkability techniques like data abstraction, anonymization, and pseudonymization can enable the identification and tracking of users across different services and over time. Anonymization, through methods like randomization or generalization, irreversibly de-identifies individuals by removing or altering data, such as obfuscating location or scrambling sensitive attributes. In contrast, pseudonymization replaces identifiable data with tokens or hashed values, making it more secure but still technically reversible under certain conditions.

This lack of privacy safeguards can result in unauthorized profiling, targeted advertising without consent, and potential legal liabilities due to non-compliance with privacy regulations.

## Modes of Introduction

- **Lack of Anonymization or Pseudonymization Measures**: Failure to remove direct identifiers, such as user ID or name, from data before server-side collection, or to manipulate the data to prevent linkage to real-world identities. This also includes not implementing protocols like Private Information Retrieval or Oblivious HTTP (OHTTP) to enhance privacy.

## Impact

- **Violation of User Privacy**: Users may not be aware that their personal information is being collected for tracking purposes, leading to privacy infringement.
- **Compliance and Legal Risks**: Breach of data protection laws and regulations (like GDPR), resulting in legal consequences and fines.

## Mitigations

- **Use Anonymisation and Pseudonymisation**: Ensure techniques like anonymisation and pseudonymisation are implemented to prevent user identification.
