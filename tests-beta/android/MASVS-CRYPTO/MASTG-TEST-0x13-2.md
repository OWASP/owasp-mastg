---
platform: android
title: Hardcoded Keys for Symmetric Cryptography
id: MASTG-TEST-0x13
type: [static, dynamic]
weakness: MASWE-0013

---

## Overview

Make sure the mobile app does not use cryptographic algorithms and protocols that have [known weaknesses or are otherwise insufficient](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms).
Note that even algorithms that are certified (for example, by NIST) can become insecure over time.

Additionally, algorithms used for encryption must be standardized and open to verification. Encrypting data using any unknown, or proprietary algorithms may expose the application to different cryptographic attacks which may result in recovery of the plaintext.

## Steps

1. Use either @MASTG-TECH-0014 or @MASTG-TECH-0033 to identify all the instances of symmetric key encryption in code and look for any mechanism which loads or provides a symmetric key.
You can look for:
    - symmetric algorithms (such as `DES`, `AES`, etc.)
    - specifications for a key generator (such as `KeyGenParameterSpec`, `KeyPairGeneratorSpec`, `KeyPairGenerator`, `KeyGenerator`, `KeyProperties`, etc.)
    - classes importing `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*`

1. For each identified instance verify if the used symmetric keys:
    - are not part of the application resources
    - cannot be derived from known values
    - are not hardcoded in code

1. For each hardcoded symmetric key, verify that is not used in security-sensitive contexts as the only method of encryption.

## Observation

The output should contain a list of locations where hardcoded keys are used for symmetric encryption.

## Evaluation

The test case fails if you can find hardcoded key material being used for symmetric encryption in a security-sensitive context.

## References

- [Testing Cryptography](../../../Document/0x04g-Testing-Cryptography.md)
