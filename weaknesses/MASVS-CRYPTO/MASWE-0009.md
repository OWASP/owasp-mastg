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

The key size, also known as the key length, is dependent on the number of bits. Encryption algorithms that utilize insufficient key sizes are vulnerable to attacks, while longer keys typically entail more intricate encryption.

A weak pseudorandom number generator (PRNG) can undermine cryptographic security by generating predictable or low-entropy keys. This reduces the effectiveness of the key length and makes it easier for attackers to guess or reproduce keys. Weak PRNGs can also produce repeated patterns, leading to further vulnerabilities. Ensuring the use of strong, cryptographically secure PRNGs with high-entropy seeding is essential for robust key security.

## Impact

- **Risk of Brute-Force Attacks**:
With a shorter key length, the number of possible combinations decreases, increasing the likelihood of an attacker successfully cracking the encryption through brute force method. Not only the length, but also if the PRNG was having a predictable input.

- **Loss of  Confidentiality**:
Encryption is utilized to safeguard the confidentiality of data, allowing only authorized users to access it. Weak encryption keys can enable attackers to obtain encrypted information and exploit it.

- **Loss of Integrity**:
Weak cryptographic key generation can undermine the integrity of data, as it creates a vulnerability that attackers can exploit to tamper with or alter the information.

## Modes of Introduction

- **Third Party Libraries**:
The libraries, algorithms and cryptographic schemes used by the application are out of date.

- **Use of Insecure Algorithms**:
The use of deprecated algorithms (e.g using the 1024-bit RSA key or 160-bit ECDSA key) in an application poses significant security risks to data.

- **Weak PRNG**:
Weak PRNG can introduce vulnerabilities in cryptographic key generation by providing insufficient entropy, making it easier for attackers to guess the key.

## Mitigations

- A secure pseudorandom number generator ([PRNG](https://developer.android.com/privacy-and-security/risks/weak-prng)) should be used to avoid predictable keys.
- The key length should meet industry standards as specified in [NIST Special Publication 800-131A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) to provide long-term protection.
- Algorithms and cryptographic schemes used in third-party libraries must be verified to ensure that they are not deprecated and used properly.
