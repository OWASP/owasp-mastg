---
title: Potentially Weak Cryptography Implementations
id: MASWE-0019
alias: potentially-weak-crypto-impl
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-2]
  masvs-v2: [MASVS-CRYPTO-1, MASVS-CODE-3]
  mastg-v1: [MASTG-TEST-0061, MASTG-TEST-0014]
  cwe: [327, 1240]

refs: 
 - https://book.hacktricks.xyz/crypto-and-stego/cryptographic-algorithms
 - https://www.researchgate.net/publication/290181523_Evaluation_of_Cryptography_Usage_in_Android_Applications
 - https://www.scitepress.org/papers/2014/50563/50563.pdf
 - https://pure.tugraz.at/ws/portalfiles/portal/23858147
 - https://github.com/Wind-River/crypto-detector
 - https://github.com/Rami114/cryptoscan/
 - https://github.com/IAIK/CryptoSlice
 - https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)
 - https://developer.android.com/privacy-and-security/security-gms-provider
 - https://developer.android.com/privacy-and-security/cryptography#bc-algorithms
 - https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library
 - https://developer.android.com/privacy-and-security/cryptography#crypto_provider
 - https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
 - https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile
---

## Overview

Outdated, weak, or noncompliant cryptographic implementations, such as those that do not meet established security standards such as FIPS 140-2/3 (Federal Information Processing Standards), may use algorithms that have not been sufficiently tested or that lack certification, may not follow best practices for secure key management, or may include custom cryptographic solutions that haven't undergone rigorous peer review or formal validation.

## Impact

Custom cryptographic implementations created without following established standards make them more susceptible to attacks such as brute force or differential cryptanalysis. In addition, cryptography is notoriously difficult to implement correctly, and even small errors in a custom solution, such as incorrect padding or faulty random number generation, can completely undermine the security of the system, exposing sensitive data to attackers.

The impact associated with such defects can be very broad and difficult to predict or measure:

- **Data breaches**: Weak encryption can lead to unauthorized access to sensitive data, resulting in data breaches.
- **Compromised confidentiality, integrity, and authenticity**: The core principles of cryptography (confidentiality, integrity, and authenticity) are compromised. Attackers can decrypt, manipulate, or impersonate legitimate users or systems.

## Modes of Introduction

- **Deviation from standard libraries**: Not using well-known libraries for cryptography, such as those provided by the platforms like Conscrypt or CryptoKit, or other well-established libraries like OpenSSL, BouncyCastle, etc.
- **Use of cryptographic constants**: Hardcoded cryptographic constants are typically used to implement cryptographic algorithms. These constants include S-boxes (substitution boxes) for block ciphers, permutation tables, etc.
- **Use of low-level mathematical operations**: Low-level mathematical operations (such as bitwise operations, shifts, custom padding schemes) typically used in cryptographic algorithms.
- **High entropy code**: An indicator of cryptographic implementations or heavily obfuscated code that may hide cryptographic algorithms from reverse engineering.
- **Use of non-cryptographic functions**: Non-cryptographic functions such as Base64 encoding or XOR instead of encryption.

## Mitigations

- **Use standard cryptographic libraries and avoid custom cryptography**: Avoid developing custom cryptographic algorithms or protocols. Always prefer well-established and widely accepted cryptographic libraries such as OpenSSL, BoringSSL, or platform-specific libraries such as Android's Conscrypt and Apple's CryptoKit. These libraries have undergone extensive testing and are regularly updated to address new security threats.

- **Ensure compliance with security standards**: If you can't avoid using custom cryptography, make sure it's implemented to meet industry standards such as FIPS 140-2/3 (Federal Information Processing Standards) or the latest National Institute of Standards and Technology (NIST) recommendations.
- **Perform periodic security audits**: If using custom cryptography is unavoidable, perform regular security audits (including thorough code reviews) to identify and remediate any flaws in your custom cryptographic implementations. Engage external security experts to provide an unbiased assessment.
