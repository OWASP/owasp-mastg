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

The key length, also known as the key size, depends on the number of bits in which the message is stored. Most secure encryption algorithms are vulnerable to attacks, when that algorithm uses insufficient key sizes. In general, longer keys mean more complex encryption.


## Impact

- **Risk of Brute-Force Attacks** :
If the key length is short, there are only a few combinations to check. This makes it more likely for an attacker to crack encryption using brute force technique.

- **Loss of  Confidentiality** : 
The purpose of encryption is to ensure the confidentiality of the data ,only authorized users can access the data.Attacker can gain access to encrypted information with weak keys and can easily read and exploit it.
 
- **Loss of Integrity**:
Weak cryptographic key generation can compromise data integrity by making it
easier for an attacker to tamper or alteration of data.


## Modes of Introduction

- **Third party libraries**:
The libraries used by the application, the algorithms used and cryptographic schemes used are outdated.

- **Use of insecure algorithms**:
The use of insecure algorithms (e.g. using the 1024-bit RSA key, 128-bit AES key, 160-bit ECDSA key) in an application poses significant security risks to data.


## Mitigations

- Use keys with sufficient length for protection against brute-force attack.
- Key Length should meet industry standards and provides long-term protection.
- Algorithms and cryptographic schemes used in third-party libraries must be verified to ensure that they are not deprecated and used properly.
