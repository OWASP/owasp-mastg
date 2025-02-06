---
title: Cryptographic Keys Not Properly Protected at Rest
id: MASWE-0014
alias: crypto-keys-not-protected-at-rest
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-1]
  masvs-v2: [MASVS-CRYPTO-2, MASVS-STORAGE-1]
  cwe: [312, 318, 321]
  android-risks:
  - https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets
refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf
status: new
---

## Overview

Cryptographic keys are essential for securing sensitive data in mobile applications. However, if these keys are not properly protected at rest, they can be easily compromised. This weakness involves storing cryptographic keys in insecure locations, such as unencrypted SharedPreferences, unprotected files, hardcoding them within the application code, or including them in source control and versioning systems which may end in the final application package in production.

Attackers can decompile or reverse-engineer the app to extract hardcoded keys.

## Impact

- **Unauthorized Access**: If cryptographic keys are not properly protected, attackers may gain unauthorized access to sensitive data and potential identity theft.
- **Loss of Integrity**: Compromised keys can allow attackers to tamper with encrypted data.
- **Loss of Confidentiality**: Sensitive information can be exposed, resulting in a loss of confidentiality. Once keys are exposed, all data encrypted with those keys is at risk.

## Modes of Introduction

- **Insecure Storage Locations**: Storing cryptographic keys in unencrypted SharedPreferences, unprotected files, or other insecure locations.
- **Hardcoded Keys**: Including cryptographic keys directly in the application code, making them susceptible to extraction through decompilation and reverse-engineering.
- **Lack of Encryption**: Exporting cryptographic keys in plain text without encrypting them using a secure method.

## Mitigations

- **Use Platform Keystores**: Where possible, generate cryptographic keys dynamically on the device, rather than using predefined keys, and ensure that they are securely stored after creation. For this you can use the platform-specific keystores, such as the [Android KeyStore](https://developer.android.com/training/articles/keystore) or [iOS KeyChain](https://developer.apple.com/documentation/security/keychain_services).
- **Implement Strongest Hardware Security Solutions**: For the most critical cases and whenever [available and compatible](https://developer.android.com/privacy-and-security/keystore#HardwareSecurityModule) for the use case at hand, leverage the strongest hardware-backed security options such as [Android StrongBox](https://source.android.com/docs/security/features/keystore/strongbox) or iOS's Secure Enclave [`kSecAttrTokenIDSecureEnclave`](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave) option to ensure the highest protection including physical and side-channel attacks.
- **Use Cryptographic Key Management Systems**: Securely retrieve keys from server-side services that provide secure storage, access control, and auditing for sensitive data. For example, AWS Secrets Manager, Azure Key Vault, or Google Cloud Secret Manager are some popular managed secrets storage solutions. The app can securely retrieve the necessary secrets at runtime through secure, authenticated API calls.
- **Encrypt and Wrap Keys**: Whenever storing keys in platform keystores is not suitable for the use case or keys need to be exported, use envelope encryption (DEK+KEK) and key wrapping techniques as specified in [NIST.SP.800-175Br1 5.3.5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf) to protect cryptographic keys before storing them.
- **Follow Standard Key Management Best Practices**: Implement proper key management practices, including key rotation and robust protection mechanisms for keys in storage as outlined in [NIST.SP.800-57pt1r5 6.2.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf), ensuring availability, integrity, confidentiality, and proper association with usage, entities, and related information.
