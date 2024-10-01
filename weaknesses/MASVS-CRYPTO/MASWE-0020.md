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

Weak encryption denotes cryptographic systems or implementations that exhibit vulnerabilities to attacks, allowing unauthorized individuals to decrypt secured data with minimal effort. This vulnerability may arise from several factors, including:

1. Short key lengths
2. Deprecated algorithms
3. Poor implementation
4. Outdated protocols

## Impact

- **Loss of  Confidentiality**:   Weak encryption may enable attackers to decipher and obtain sensitive information, resulting in unauthorized exposure and possible data breaches.

- **Loss of Integrity**: Weak encryption may compromise the integrity of data, allowing adversaries to exploit vulnerabilities and potentially alter or manipulate the information without detection.

## Mode of Introduction

- **Use of Deprecated Algorithms** : Relying on outdated or weak cryptographic algorithms can produce keys that are less secure. Such algorithms are often characterized by vulnerabilities or the ability to use shorter key lengths, which increases their susceptibility to contemporary attacks and threatens the overall security of the application.

- **Inadequate Key Lengths**: Insufficiently long cryptographic keys fail to ensure robust security. For example, keys that are shorter than the advised lengths for current algorithms can be at risk of brute force attacks,thus making it easier for attackers to gain unauthorized access.

## Mitigations

- Always use modern, well-established cryptographic libraries and APIs that follow best practices for entropy generation and key management.
- Ensure that key lengths meet or exceed current standards for cryptographic security, such as 256-bit for AES encryption and 2048-bit for RSA (considering quantum computing attacks). See ["NIST Special Publication 800-57: Recommendation for Key Management: Part 1 – General"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) and ["NIST Special Publication 800-131A: Transitioning the Use of Cryptographic Algorithms and Key Lengths"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) and ["BlueKrypt's Cryptographic Key Length Recommendation"](https://www.keylength.com/) for more information on cryptographic key sizes.
