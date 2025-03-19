---
platform: android
title: Symmetric key used for multiple purposes
id: MASTG-TEST-0x15-2
type: [static, dynamic]
weakness: MASWE-0012
---

## Overview

In general, ["a single key shall be used for only one purpose (e.g., encryption, integrity
authentication, key wrapping, random bit generation, or digital signatures)"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf).
Reusing the same key multiple purposes may weaken its security or increase the impact of one key being compromised.

This does not apply to the cases where the same process can provide multiple services, e.g., a single symmetric key can be used to encrypt and authenticate data in a single operation (one authenticated-encryption operation instead of separate encryption and authentication operations).
Check ["NIST.SP.800-57pt1r5"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) for details.

## Steps

1. Use either @MASTG-TECH-0014 or @MASTG-TECH-0033 to identify all the where symmetric cryptography is used.
You can look for uses of:
    - classes `Cipher`, `Mac`,
    - interfaces `Key`, `SecretKey`
    - functions `getInstance`, `generateKey`, `generateKeyPair`
    - exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
    - classes importing `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*`

## Observation

The observation contains all the uses of each `Key` object with backtraces to know the locations.

## Evaluation

Reverse engineer the observed backtraces and try to determine the "business purpose" for which each `Key` object is being used:

1. For each identified instance, identify the process for which cryptography is being used:
    - for encryption/decryption - to ensure data confidentiality
    - for maintenance - to protect keys during certain sensitive operations (such as being imported to the `KeyStore`)
1. Identify the business logic which uses identified instances of cryptography.

The test case fails if there is a `Key` object that is being used for multiple business purposes.

## References

- [NIST.SP.800 - Recommendation for Key Management (part 1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
