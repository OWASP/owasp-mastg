---
title: Signatures Created by Deprecated, Risky or Broken Algorithms
id: MASWE-0025
alias: weak-signatures
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  cwe: [327]

refs:
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
- https://csrc.nist.gov/pubs/ir/8547/ipd
draft:
  description: The use of algorithms with insufficient strength for signatures such as SHA1withRSA, etc. in a security sensitive context should be avoided to ensure the integrity and authenticity of the data.
  topics: null
status: draft

---
Using deprecated, risky or broken algorithms for the purpose of ensuring accountability and non-reputation through the use of signatures could make it possible for an attacker to execute digital signature forgery and compromise the integrity and authenticity of the data at rest and in transit.

## Impact

- **Loss of Integrity and authenticity**: Signature forgery may allow the attacker to compromise the integrity and authenticity of the data by signing the data on behalf of another entity.
- **Loss of accountability**: Signature forgery allows for plausible deniability and diminishes accountability.

## Modes of Introduction

- **Using a deprecated, risky or broken hashing algorithm**: e.g. MD5 and SHA-1 have been identified to be vulnerable for collision attacks that are faster than a birthday attack. Because of this they are denounced as "broken".
- **Using a insufficiently collision resistant hash**: Choosing a hashing algorithm of insufficient length may result in loss of integrity or confidentiality.

## Mitigations

- **Choose collision resistant algorithm**: Choose a signature algorithm that is sufficiently collision resistant like RSA (3072 bits and higher), ECDSA with NIST P-384 or EdDSA with Edwards448.

- **Choose a signing scheme that make use of algorithms with sufficient bit-lengths**: As our computers gets stronger, previously generated hashes get weaker, therefore, make sure that you can adjust the bit-length length (strength) of the algorithm of your choosing. When signatures are stored at rest, make sure to follow the software industry's long term recommendations (e.g. ["NIST: Transition to Post-Quantum Cryptography Standards"](https://csrc.nist.gov/pubs/ir/8547/ipd)).
