---
title: Weak Encryption Algorithms
platform: android
id: MASTG-TEST-0221
type: [static, dynamic]
weakness: MASWE-0020
---

## Overview

To test for the [use of weak encryption algorithms](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) in Android apps, we need to focus on methods from cryptographic frameworks and libraries that are used to perform encryption and decryption operations.

- [`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)): Initializes a Cipher object for encryption or decryption. The `algorithm` parameter can be one of the [supported algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher).
- [`SecretKeyFactory.getInstance`](https://developer.android.com/reference/javax/crypto/SecretKeyFactory#getInstance(java.lang.String)): Returns a SecretKeyFactory object that converts keys into key specifications and vice versa. The `algorithm` parameter can be one of the [supported algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory).
- [`KeyGenerator.getInstance`](https://developer.android.com/reference/javax/crypto/KeyGenerator#getInstance(java.lang.String)): Returns a `KeyGenerator` object that generates secret keys for symmetric algorithms. The `algorithm` parameter can be one of the [supported algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyGenerator).

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and look for uses of the cryptographic functions that perform encryption and decryption operations.

## Observation

The output should contain a list of locations where insecure symmetric encryption algorithms are used.

## Evaluation

The test case fails if you can find [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) encryption algorithms being used.

For example, [DES (Data Encryption Standard) and 3DES (Triple DES)](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm), are deprecated by [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final) due to vulnerabilities such as brute-force attacks and meet-in-the-middle attacks. Replace them with stronger alternatives, such as [AES-256](https://developer.android.com/privacy-and-security/cryptography#choose-algorithm), which is widely recognized as secure for modern apps.
