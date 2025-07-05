---
platform: android
title: Insufficient Key Sizes 
id: MASTG-TEST-0208
type: [static]
weakness: MASWE-0009
profiles: [L1, L2]
---

## Overview

In this test case, we will look for the use insufficient key sizes in Android apps. To do this, we need to focus on the cryptographic frameworks and libraries that are available in Android and the methods that are used to generate, inspect and manage cryptographic keys.

The Java Cryptography Architecture (JCA) provides foundational classes for key generation which are often used directly when portability or compatibility with older systems is a concern.

- **`KeyGenerator`**: The [`KeyGenerator`](https://developer.android.com/reference/javax/crypto/KeyGenerator) class is used to generate symmetric keys including AES, DES, ChaCha20 or Blowfish, as well as various HMAC keys. The key size can be specified using the [`init(int keysize)`](https://developer.android.com/reference/javax/crypto/KeyGenerator#init(int)) method.
- **`KeyPairGenerator`**: The [`KeyPairGenerator`](https://developer.android.com/reference/java/security/KeyPairGenerator) class is used for generating key pairs for asymmetric encryption (e.g., RSA, EC). The key size can be specified using the [`initialize(int keysize)`](https://developer.android.com/reference/java/security/KeyPairGenerator#initialize(int)) method.

For more information you can consult the MASTG section about ["Key Generation"](../../../Document/0x05e-Testing-Cryptography.md#key-generation).

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the cryptographic functions that generate keys.

## Observation

The output should contain a list of locations where insufficient key lengths are used.

## Evaluation

The test case fails if you can find the use of insufficient key sizes within the source code. For example, a 1024-bit key size is considered insufficient for RSA encryption and a 128-bit key size is considered insufficient for AES encryption considering quantum computing attacks.
