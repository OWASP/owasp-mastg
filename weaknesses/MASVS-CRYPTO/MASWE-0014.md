---
title: Cryptographic Keys Not Properly Protected at Rest
id: MASWE-0014
alias: crypto-keys-not-protected-at-rest
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-1]
  masvs-v2: [MASVS-CRYPTO-2, MASVS-STORAGE-1]
refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf
status: new
---

## Overview

Cryptographic keys are essential for securing sensitive data in mobile applications. However, if these keys are not properly protected at rest, they can be easily compromised. This weakness involves storing cryptographic keys in insecure locations, such as SharedPreferences, files, or hardcoding them within the application code.

## Impact

- **Unauthorized Access**: If cryptographic keys are not properly protected, attackers can gain unauthorized access to sensitive data, leading to data breaches and potential identity theft.
- **Data Tampering**: Compromised keys can allow attackers to tamper with encrypted data, leading to data integrity issues.
- **Loss of Confidentiality**: Sensitive information can be exposed if cryptographic keys are not securely stored, resulting in a loss of confidentiality.

## Modes of Introduction

- **Insecure Storage Locations**: Storing cryptographic keys in SharedPreferences, files, or other insecure locations.
- **Hardcoded Keys**: Including cryptographic keys directly in the application code.
- **Lack of Encryption**: Storing cryptographic keys without encrypting them using a secure method.

## Mitigations

- **Use Platform Keystores**: Utilize platform-specific keystores, such as the Android KeyStore or iOS KeyChain, to securely store cryptographic keys.
- **Encrypt Keys**: Use envelope encryption (DEK+KEK) to encrypt cryptographic keys before storing them.
- **Key Wrapping**: Implement key wrapping techniques as recommended by [NIST.SP.800-175Br1 5.3.5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf) to protect keys during storage and transmission.
- **Trusted Execution Environment (TEE)/Secure Element (SE)**: Leverage TEE or SE to provide hardware-backed security for cryptographic keys.
