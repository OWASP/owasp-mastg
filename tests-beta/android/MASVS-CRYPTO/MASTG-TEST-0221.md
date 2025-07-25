---
title: Broken Symmetric Encryption Algorithms
platform: android
id: MASTG-TEST-0221
type: [static, dynamic]
weakness: MASWE-0020
best-practices: [MASTG-BEST-0009]
profiles: [L1, L2]
---

## Overview

To test for the [use of broken encryption algorithms](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) in Android apps, we need to focus on methods from cryptographic frameworks and libraries that are used to perform encryption and decryption operations.

- [`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)): Initializes a Cipher object for encryption or decryption. The `algorithm` parameter can be one of the [supported algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher).
- [`SecretKeyFactory.getInstance`](https://developer.android.com/reference/javax/crypto/SecretKeyFactory#getInstance(java.lang.String)): Returns a SecretKeyFactory object that converts keys into key specifications and vice versa. The `algorithm` parameter can be one of the [supported algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory).
- [`KeyGenerator.getInstance`](https://developer.android.com/reference/javax/crypto/KeyGenerator#getInstance(java.lang.String)): Returns a `KeyGenerator` object that generates secret keys for symmetric algorithms. The `algorithm` parameter can be one of the [supported algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyGenerator).

Some broken symmetric encryption algorithms include:

- **DES (Data Encryption Standard)**: 56-bit key, breakable, [withdrawn by NIST in 2005](https://csrc.nist.gov/pubs/fips/46-3/final).
- **3DES (Triple DES, officially the Triple Data Encryption Algorithm (TDEA or Triple DEA))**: 64-bit block size, [vulnerable to Sweet32 birthday attacks](https://sweet32.info/), [withdrawn by NIST on January 1, 2024](https://csrc.nist.gov/pubs/sp/800/67/r2/final).
- **RC4**: Predictable key stream, allows plaintext recovery [RC4 Weakness](https://www.rc4nomore.com/), disapproved by [NIST](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-52r1.pdf) in 2014 and prohibited by [IETF](https://datatracker.ietf.org/doc/html/rfc7465) in 2015.
- **Blowfish**: 64-bit block size, [vulnerable to Sweet32 attacks](https://en.wikipedia.org/wiki/Birthday_attack), never FIPS-approved, and listed under ["Non-Approved algorithms" in FIPS](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp2092.pdf).

Android also provides additional guidance on [broken cryptographic algorithms](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm).

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and look for uses of the cryptographic functions that perform encryption and decryption operations.

## Observation

The output should contain a list of locations where insecure symmetric encryption algorithms are used.

## Evaluation

The test case fails if you can find [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) encryption algorithms being used.
