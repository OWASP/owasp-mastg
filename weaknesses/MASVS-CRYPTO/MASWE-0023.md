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
---

## Overview

Outdated or weak padding schemes, such as PKCS1v1.5 or other padding schemes that fail to comply with secure standards, such as NIST SP 800-56B are not recommended for use. These padding schemes include vulnerabilities that may allow attackers to undermine security mechanisms, such as padding oracle attacks.

## Impact

Weak padding schemes can completely undermine the security of the cryptographic algorithms, exposing sensitive data to attackers, and making systems vulnerable to various attacks. This can lead to:

- **Data breaches**: Weak padding can lead to unauthorized access to sensitive data, resulting in data breaches.
- **Loss of data integrity**: Padding attacks may aid attackers in manipulating ciphertext, leading to unauthorized data modifications.
- **Compromised confidentiality**: Weak padding may aid attackers in recovering plaintext from encrypted data.

## Modes of Introduction

- **Insecure padding scheme**: Using padding schemes that are vulnerable to attacks, such as PKCS1V1.5 or PKCS#7 when used with CBC mode of operation.
- **Custom padding solutions**: Implementing custom or non-standard padding schemes that have not been sufficiently tested or that lack certification.
- **Improper padding validation**: Failure to correctly validate and handle padding errors, potentially leaking information to attackers via error messages or timing discrepancies.
- **Outdated cryptographic libraries**: Using libraries or algorithms with known padding vulnerabilities (e.g. Padding Oracle).

## Mitigations

- **Use standard cryptographic libraries and avoid custom cryptography**: Avoid developing custom cryptographic algorithms with custom padding schemes. Always prefer well-established and widely accepted cryptographic libraries such as OpenSSL, BoringSSL, or platform-specific libraries such as Android's Conscrypt and Apple's CryptoKit. These libraries have undergone extensive testing and are regularly updated to address new security threats.
- **Implement proper and secure padding validation**: Use established and secure padding schemes, ensuring that padding is properly validated when necessary for the encryption mode. When possible, use authenticated encryption modes like GCM, which eliminate the need for padding and include built-in integrity verification.
- **Regularly update cryptographic libraries**: Ensure the cryptographic libraries in use are up-to-date to avoid known vulnerabilities related to padding attacks.
- **Perform periodic security audits**: If using custom cryptography is unavoidable, perform regular security audits (including thorough code reviews) to identify and remediate any flaws in your custom cryptographic implementations. Engage external security experts to provide an unbiased assessment.