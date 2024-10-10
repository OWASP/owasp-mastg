---
title: Weak Encryption
id: MASWE-0020
alias: weak-encryption
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]

refs:
- https://support.google.com/faqs/answer/10046138?hl=en
- https://support.google.com/faqs/answer/9450925?hl=en
- https://support.google.com/faqs/answer/9450925?hl=en
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
draft:
  description: The use of outdated encryption methods like DES and 3DES may compromise
    data confidentiality and integrity.
  topics:
  - Weak encryption algorithms (e.g. DES, 3DES, etc.)
  - Weak encryption modes (e.g. ECB, etc.)
  - Cipher.getInstance("AES") defaults to ECB (Android)
status: draft

---

## Overview

Weak encryption denotes cryptographic systems or implementations that exhibit vulnerabilities to attacks, allowing unauthorized individuals to decrypt secured data with minimal effort. This inadequacy may arise from various reasons, such as, use of outdated algorithms, short key lengths, weak encryption modes(ECB) and improper implementation practices. For instance, the DES encryption standard, once considered robust, is now vulnerable to brute-force attacks because its key sizes are too small to withstand the capabilities of contemporary computing power. In a similar, hash functions like MD5 and SHA-1, which were previously popular for ensuring data integrity, are now deemed weak as attackers can easily generate hash collisions, resulting in security breaches.

## Impact

- **Loss of  Confidentiality**: Weak encryption may enable attackers to decipher and obtain sensitive information, resulting in unauthorized exposure and possible data breaches.

- **Loss of Integrity**: Weak encryption may compromise the integrity of data, allowing adversaries to exploit vulnerabilities and potentially alter or manipulate the information without detection.

## Mode of Introduction

- **Use of Deprecated Algorithms** : Relying on outdated or weak cryptographic algorithms can produce keys that are less secure. Such algorithms are often characterized by vulnerabilities or the ability to use shorter key lengths, which increases their susceptibility to contemporary attacks and threatens the overall security of the application.

## Mitigations

- Always use modern, well-established cryptographic libraries and APIs that follow best practices for entropy generation and key management.
- It is recommended to use secure modes of Operation like CBC (Cipher Block Chaining).
