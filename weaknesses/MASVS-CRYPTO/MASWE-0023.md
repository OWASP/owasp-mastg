---
title: Weak Padding
id: MASWE-0023
alias: weak-padding
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  mastg-v1: [MASTG-TEST-0014]

refs:
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
- https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
- https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile
- https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf
status: new
---

## Overview

Outdated or weak padding schemes, such as PKCS1v1.5 or other padding schemes that fail to comply with secure standards, as outlined in [NIST SP 800-131A Rev.2, Section 6 Key Agreement and Key Transport Using RSA](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) are not recommended for use. These padding schemes include vulnerabilities that may allow attackers to undermine security mechanisms, such as [padding oracle attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf).

## Impact

- **Loss of data integrity**: Padding attacks can help attackers manipulate ciphertext, leading to unauthorized data modifications. By modifying the ciphertext and observing how the system responds, attackers can alter encrypted data in a way that the system decrypts it without detecting any issues. This allows the system to accept the altered data as valid, compromising its integrity.
- **Compromised confidentiality**: Weak padding can enable attackers to recover plaintext from encrypted data. Vulnerable implementations may leak information about the correctness of padding through error messages, which attackers can use to gradually decrypt sensitive information such as passwords or session tokens, compromising the confidentiality of the data.

## Modes of Introduction

- **Insecure padding scheme**: Using padding schemes that are vulnerable to attacks, such as PKCS1V1.5 or PKCS#7 when used with CBC mode of operation.
- **Custom padding solutions**: Implementing custom or non-standard padding schemes that have not been sufficiently tested or that lack certification.
- **Improper padding validation**: Failure to correctly validate and handle padding errors, potentially leaking information to attackers via error messages or timing discrepancies.

## Mitigations

- **Implement proper and secure padding validation**: Use established and secure padding schemes, ensuring that padding is properly validated when necessary for the encryption mode. When possible, use authenticated encryption modes like GCM, which eliminate the need for padding and include built-in integrity verification.
