---
title: Potentially Weak Cryptography Implementations
alias: potentially-weak-crypto-impl
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-2]
  masvs-v2: [MASVS-CRYPTO-1, MASVS-CODE-3]
  mastg-v1: [MASTG-TEST-0061, MASTG-TEST-0014]

refs: 
 - https://cwe.mitre.org/data/definitions/1240.html
 - https://cwe.mitre.org/data/definitions/327.html
 - https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)
 - https://developer.android.com/privacy-and-security/security-gms-provider
 - https://developer.android.com/privacy-and-security/cryptography#bc-algorithms
 - https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library
 - https://developer.android.com/privacy-and-security/cryptography#crypto_provider
 - https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
 - https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile
---

## Overview

The use of outdated or known weak implementations, as well as custom built cryptography poses a significant security risk, as their potential implementation flaws and lack of security review exposes apps to vulnerabilities. Instead, always use certified, expert-designed modules for cryptographic purposes.

## Impact

Custom cryptographic implementations created without following established standards make them more susceptible to attacks such as brute force or differential cryptanalysis. In addition, cryptography is notoriously difficult to implement correctly, and even small errors in a custom solution, such as incorrect padding or faulty random number generation, can completely undermine the security of the system, exposing sensitive data to attackers.

The impact associated with such defects can be very broad and difficult to predict or measure:

- **Data breaches**: Weak encryption can lead to unauthorized access to sensitive data, resulting in data breaches.
- **Compromised confidentiality, integrity, and authenticity**: The core principles of cryptography (confidentiality, integrity, and authenticity) are compromised. Attackers can decrypt, manipulate, or impersonate legitimate users or systems.

## Modes of Introduction

Weak, outdated or custom cryptographic algorithms can be found in several areas:

- **App Source Code**: In modules where cryptographic algorithms are used.
- **Libraries**: Third-party or app dependencies where cryptographic algorithms are imported.

## Mitigations

To mitigate the risks associated with weak cryptographic implementations, developers should:

- Use strong and up-to-date cryptographic algorithms to manage data.
- Do not implement custom-made cryptographic algorithms, as they may be exposed to attacks.
- Manage and protect cryptoghraphic keys, using Android KeyStore or iOS Keychain.
- When using cryptographic algorithms, do not omit steps in order to improve performance. These steps are often essential for preventing attacks.
- Regularly audit the codebase and dependencies for outdated cryptographic algorithms.
- Security crypto libraries such as Jetpack or BouncyCastle are deprecated for many algorithms, avoid using them.
