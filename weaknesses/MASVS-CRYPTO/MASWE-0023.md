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
- https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile
- https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf
- https://capec.mitre.org/data/definitions/463.html
- https://robertheaton.com/2013/07/29/padding-oracle-attack/
status: new
---

## Overview

Outdated or weak padding schemes are discouraged due to vulnerabilities that enable [padding oracle attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf).

- **Symmetric Cryptography**: PKCS#7 padding is vulnerable to padding oracle attacks unless mitigations like AES-GCM or HMAC are used. PKCS#7 padding is used for symmetric encryption algorithms like AES in block cipher modes (e.g., CBC). PKCS#7 has been superseded by CMS (Cryptographic Message Syntax), defined in RFC 5652.
- **Asymmetric Cryptography**: PKCS#1 v1.5 specifies padding schemes for RSA operations and is vulnerable to attacks like Bleichenbacher's. Its use is disallowed by NIST starting December 31, 2023, see [NIST SP 800-131A Rev.2, Section 6 Key Agreement and Key Transport Using RSA](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf).

A padding oracle attack is a side-channel attack, where an adversary can decrypt and encrypt data without knowing the decryption key.

The mere use of weak padding schemes does not necessarily imply the presence of a padding oracle vulnerability. However, weak padding schemes create the conditions for such attacks. Success depends on whether exploitable system behaviors, such as detailed error messages or timing differences, exist.

- **Lack of Message Authentication**: The decryption routine does not properly authenticate the message or verify its integrity before performing the decryption operation (e.g., AES-CBC with PKCS#7 padding).
- **Padding Oracle**: The target app leaks data (e.g., logs, error messages, timing differences) indicating whether a padding error occurred during decryption. This feedback becomes the "padding oracle," allowing attackers to infer the correctness of padding through iterative observations.

## Impact

- **Loss of Integrity**: Attackers can modify ciphertext, exploiting the padding oracle to trick the system into accepting maliciously altered data, leading to unauthorized data modifications.
- **Loss of Confidentiality**: Attackers can use the padding oracle to iteratively decrypt sensitive information, such as passwords or session tokens, leading to exposure of confidential data.

## Modes of Introduction

- **Insecure Padding for Asymmetric Encryption**: Using weak padding schemes like PKCS#1 v1.5 for RSA asymmetric encryption.
- **Insecure Padding for Symmetric Encryption**: Using padding schemes like PKCS#7 without additional message authentication (e.g., HMAC) for symmetric encryption algorithms like AES in block cipher modes (e.g., CBC).

## Mitigations

- **Use Secure Padding Schemes for Asymmetric Encryption**: Replace weak schemes like PKCS#1 v1.5 with secure ones such as OAEP (Optimal Asymmetric Encryption Padding).
- **Use Authenticated Symmetric Encryption Modes**: Prefer authenticated encryption modes like AES-GCM, which eliminate the need for separate padding validation and incorporate integrity checks. If AES-CBC must be used, adopt the Encrypt-then-MAC paradigm (e.g., append HMAC).
- **Don't Expose Cryptographic Errors**: Do not expose cryptographic error messages, such as padding errors, to users. This prevents attackers from gaining clues about the padding's correctness.
