---
title: Weak Cryptographic Key Generation
id: MASWE-0009
alias: weak-crypto-key-generation
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-2]
  masvs-v2: [MASVS-CRYPTO-2]
  cwe: [326, 327, 337, 338]
  android: 
    - https://developer.android.com/privacy-and-security/risks/weak-prng
    - https://developer.android.com/privacy-and-security/cryptography
refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf

---

## Overview


In cryptography, the security strength is heavily influenced by the methods used to generate cryptographic keys. One critical aspect is the key size, also known as the key length, which is measured in bits and must comply with the latest security best practices. Encryption algorithms that use insufficient key sizes are vulnerable to attack, while longer keys typically result in more complex encryption.

A weak pseudorandom number generator (PRNG) can undermine cryptographic security by generating predictable or low-entropy keys. This reduces the effectiveness of the key length and makes it easier for attackers to guess or reproduce keys. Weak PRNGs can also produce repeated patterns, leading to further vulnerabilities. Ensuring the use of strong, cryptographically secure PRNGs with high-entropy seeding is essential for robust key security.

## Impact

- **Risk of Brute-Force Attacks**:
A shorter key length increases the likelihood of an attacker successfully cracking the encryption using brute force attacks; not only the length, but also whether the PRNG had a predictable input can be exploited in brute force attacks.

- **Loss of  Confidentiality**:
Encryption is used to safeguard the confidentiality of data so that only authorized users can access it. Weak encryption keys can allow attackers to obtain encrypted information for disclosure and unauthorized access.

- **Loss of Integrity**:
Weak cryptographic key generation can undermine the integrity of data, as it creates a vulnerability that attackers can exploit to tamper with or alter the information.

## Modes of Introduction

- **Use of Insecure Algorithms**:
Using deprecated algorithms (such as the 1024-bit RSA key or 160-bit ECDSA key) in an application poses significant security risks to data.

- **Weak PRNG**:
A weak PRNG can introduce vulnerabilities in cryptographic key generation by providing insufficient entropy, making it easier for attackers to guess the key.

- **Relying on Non-Standard Implementations**:
Relying on non-standard methods for encryption, such as using the `random()` method or encoding techniques like Base64, can lead to weak or reversible cipher texts.

- **Third Party Libraries**:
The algorithms, cryptographic schemes and key sizes offered by a third party library are out of date.

## Mitigations

- The cryptographic schemes and key length used in the app and third-party libraries should meet industry standards as specified in [NIST Special Publication 800-131A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) to provide long-term protection.
