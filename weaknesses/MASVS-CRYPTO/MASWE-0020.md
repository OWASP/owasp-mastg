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

Weak encryption refers to cryptographic systems or implementations that are vulnerable to attack, allowing unauthorised individuals to decrypt secured data. This weakness can be due to a number of reasons, including the use of outdated algorithms, deprecated encryption modes such as ECB and improper implementation practices such as the use of a non-random or empty Initialisation Vector (IV). 

For example the use of TDEA (Triple Data Encryption Algorithm), which is often referred to as "Triple DES" or "3DES" is disallowed by NIST since end of 2023, due to known attacks like, "meet-in-the-middle", collision attacks and [Sweet32](https://nvd.nist.gov/vuln/detail/CVE-2016-2183).

Similarly, hash functions such as MD5 and SHA-1, which were previously popular for ensuring data integrity, are now considered deprecated as attackers can generate hash collisions, potentially leading to data tampering.

## Impact

- **Loss of Confidentiality**: Weak encryption may enable attackers to decipher and obtain sensitive information, resulting in unauthorized exposure and possible data breaches.

- **Loss of Integrity**: Weak encryption can compromise the integrity of data, allowing adversaries to alter or manipulate the information without detection.

## Mode of Introduction

- **Use of Deprecated Algorithms** : Relying on outdated or weak cryptographic algorithms can allow threat actors to attack the cipher text, key or exploit known vulnerabilities in the algorithm, for example through brute force attacks.
- **Insecure Modes of Operation**:  Using modes that are considered deprecated increase the attack surface of encrypted information. For example the use of AES/ECB is deprecated as it divides the plaintext into blocks and encrypts each block separately using the same key. This makes the cipher text vulnerable to "known plaintext attacks" and leaks information about the structure of the original plaintext. 
- **Predictable Initialization Vectors (IVs)**: If IVs are not random or unique, they can be exploited in attacks like ciphertext injection or pattern recognition. This compromises the confidentiality of encrypted data, especially in modes like CBC (Cipher Block Chaining).
- **Weak Keys**: Short or easily guessable keys compromise encryption strength. The use of small key sizes (e.g., 56-bit keys in DES) can make the encryption susceptible to brute-force attacks. Best practices recommend keys of at least 256 bits for strong encryption.
- **Misuse of Non-Cryptographic Operations**: Relying on techniques such as XOR, Base64 encoding, or simple obfuscation methods for security purposes. These methods provide no actual encryption and can be easily reversed or decoded, exposing sensitive data.

## Mitigations

- Always use modern, well-established cryptographic libraries in mobile apps that follow best practices and offer cryptographic algorithms that are aligned with the recommendations by NIST.
- For example it is recommended to use secure modes of operations like GCM (Galois/Counter Mode) mode for AES with 256-bit keys, providing both encryption and authentication.
