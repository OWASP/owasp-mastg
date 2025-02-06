---
title: Weak Encryption
id: MASWE-0020
alias: weak-encryption
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  cwe: [326]

refs:
- https://support.google.com/faqs/answer/10046138?hl=en
- https://support.google.com/faqs/answer/9450925?hl=en
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf

status: new

---

## Overview

Weak encryption refers to cryptographic systems or implementations that are vulnerable to attack, allowing unauthorised individuals to decrypt secured data. This weakness can be due to a number of reasons, including the use of outdated algorithms, deprecated encryption modes such as ECB and improper implementation practices such as the use of a non-random or empty Initialisation Vector (IV).

## Impact

- **Loss of Confidentiality**: Weak encryption may enable attackers to decipher and obtain sensitive information, resulting in unauthorized exposure and possible data breaches.

- **Loss of Integrity**: Weak encryption can compromise the integrity of data, allowing adversaries to alter or manipulate the information without detection.

## Mode of Introduction

- **Use of Deprecated Algorithms** : Relying on outdated or weak encryption algorithms can allow threat actors to attack the cipher text, key or exploit known vulnerabilities in the algorithm, for example through brute force attacks.
- **Insecure Modes of Operation**:  Using modes that are considered deprecated increase the attack surface of encrypted information. For example the use of AES/ECB is deprecated as it divides the plaintext into blocks and encrypts each block separately using the same key. This makes the cipher text vulnerable to "known plaintext attacks" and leaks information about the structure of the original plaintext.
- **Predictable Initialization Vectors (IVs)**: If IVs are not random or unique, they can be exploited in attacks like ciphertext injection or pattern recognition. This compromises the confidentiality of encrypted data, especially in modes like CBC (Cipher Block Chaining).
- **Weak Keys**: Short or easily guessable keys compromise encryption strength. The use of small key sizes (e.g., 56-bit keys in DES) can make the encryption susceptible to brute-force attacks. Best practices recommend keys of at least 256 bits for strong encryption.
- **Misuse of Non-Cryptographic Operations**: Relying on techniques such as XOR, Base64 encoding, or simple obfuscation methods for security purposes. These methods provide no actual encryption and can be easily reversed or decoded, exposing sensitive data.

## Mitigations

- **Use Secure Encryption Modes**: Choose secure modes such as `AES/GCM/NoPadding` and avoid insecure modes such as ECB.  
- **Ensure Proper Initialization Vector Management**: Generate IVs using cryptographically secure random number generators and ensure they are unique for every operation.
- **Use Strong Key Sizes**: Enforce key lengths of at least 256 bits for AES and avoid using small or weak keys such as 56-bit DES keys.  
- **Rely on Proper Cryptographic Libraries**: Avoid using XOR, Base64 encoding, or obfuscation as substitutes for encryption and rely on well-vetted cryptographic libraries.
