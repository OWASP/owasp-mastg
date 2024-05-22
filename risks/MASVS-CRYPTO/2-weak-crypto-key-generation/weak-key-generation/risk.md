---
title: Weak Cryptographic Key Generation 
alias: weak-crypto-key-generation
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-2]
  masvs-v2: [MASVS-CRYPTO-2]
  mastg-v1: [MASTG-TEST-0061, MASTG-TEST-0014]
---

## Overview

The key size, also known as the key length, is dependent on the number of bits in which the message is stored. Encryption algorithms that utilize insufficient key sizes are vulnerable to attacks, while longer keys typically entail more intricate encryption.


## Impact

- **Risk of Brute-Force Attacks**:
With a shorter key length, the number of possible combinations decreases, increasing the likelihood of an attacker successfully cracking the encryption through brute force method.

- **Loss of  Confidentiality**:
Encryption is utilized to safeguard the confidentiality of data, allowing only authorized users to access it. Weak encryption keys can enable attackers to obtain encrypted information and exploit it effortlessly.
 
- **Loss of Integrity**:
Weak cryptographic key generation can undermine the integrity of data, as it creates a vulnerability that attackers can exploit to tamper with or alter the information.


## Modes of Introduction

- **Third Party Libraries**:
The libraries used by the application, the algorithms used and cryptographic schemes used are outdated.

- **Use of Insecure Algorithms**:
The use of insecure algorithms (e.g using the 1024-bit RSA key, 128-bit AES key, 160-bit ECDSA key) in an application poses significant security risks to data.


## Mitigations

- Utilize keys that are long enough to safeguard against brute-force attacks.
- Key Length should meet [industry standards](https://www.keylength.com/en/4/) and provides long-term protection.
- Algorithms and cryptographic schemes used in third-party libraries must be verified to ensure that they are not deprecated and used properly.
