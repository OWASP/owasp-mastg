---
platform: android
title: Insecure Algorithms for Symmetric Cryptography
id: MASTG-TEST-0x13
type: [static, dynamic]
weakness: MASWE-0020
---


## Overview

Make sure the mobile app does not use cryptographic algorithms and protocols that have [known weaknesses or are otherwise insufficient](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms).
Note that even algorithms that are certified (for example, by NIST) can become insecure over time.

Additionally, algorithms used for encryption must be standardized and open to verification. Encrypting data using any unknown, or proprietary algorithms may expose the application to different cryptographic attacks which may result in recovery of the plaintext.

## Steps

1. Identify all the instances of symmetric key encryption in code, using either @MASTG-TECH-0014 or @MASTG-TECH-0033.
Look for APIs that create symmetric encryption ciphers or keys, such as:
    - [`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String))
    - [`SecretKeyFactory.getInstance`](https://developer.android.com/reference/javax/crypto/SecretKeyFactory#getInstance(java.lang.String))
    - [`KeyGenerator.getInstance`](https://developer.android.com/reference/javax/crypto/KeyGenerator#getInstance(java.lang.String))

1. Check if the used algorithms are considered [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms).

## Observation

The output should contain a list of locations where insecure symmetric encryption algorithms are used.

## Evaluation

The test case fails if you can find insecure symmetric encryption algorithms being used.

## References

- [Testing Cryptography](../../../Document/0x04g-Testing-Cryptography.md)
