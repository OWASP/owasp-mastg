---
title: Improper Encryption
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

Improper encryption refers to cryptographic systems or implementations that are vulnerable to attack, allowing unauthorized individuals to decrypt secured data.

## Impact

- **Loss of Confidentiality**: Improper encryption may enable attackers to decipher and obtain sensitive information, resulting in unauthorized exposure and possible data breaches.
- **Loss of Integrity**: Improper encryption can compromise the integrity of data, allowing adversaries to alter or manipulate the information without detection.

## Mode of Introduction

- **Broken Algorithms**: Relying on broken encryption algorithms (i.e., that are deprecated or disallowed by NIST or other standards) such as RC4.
- **Risky Algorithm Configurations**: Using IVs with insufficient entropy or reusing them in modes like AES-CBC or AES-CTR breaks semantic security, allowing attackers to detect patterns or recover plaintext differences. In AEAD modes like AES-GCM, reusing nonces or using authentication tags of insufficient length compromises both confidentiality and integrity.
- **Broken Modes of Operation**: Using modes that are considered broken. For example, AES-ECB is broken due to practical known-plaintext attacks and it's disallowed by NIST.
- **Insufficient Key Length**: The use of insufficient key sizes (e.g., 128-bit keys in AES) can compromise encryption strength making the encryption susceptible to brute-force attacks.
- **Non-Cryptographic Operations**: Relying on techniques such as XOR, Base64 encoding, or simple obfuscation methods for security purposes. These methods provide no actual encryption and can be easily reversed or decoded, exposing sensitive data.

## Mitigations

- **Use Secure Encryption Modes**: Choose secure modes (e.g. approved by NIST) such as `AES/GCM/NoPadding`.
- **Ensure Proper Initialization Vector Management**: Generate IVs using cryptographically secure random number generators (with sufficient entropy) and ensure they are unique for every operation.
- **Use Sufficiently Long Keys**: Enforce sufficiently long keys such as those approved by NIST, e.g., a minimum of 256 bits for AES.
- **Rely on Proper Cryptographic Primitives**: Rely on well-vetted cryptographic primitives that have undergone rigorous peer review and formal validation.
