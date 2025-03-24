---
platform: android
title: Weak Message Authentication Codes (MAC) Algorithms
id: MASTG-TEST-0x14
type: [static, dynamic]
weakness: MASWE-0024	
---

## Overview

When apps need to use hashing in security sensitive scenarios, appropriate algorithms should be used.

--  MASTG-TEST-0014 -- 
Identify all the instances of the cryptographic primitives in code. Identify all custom cryptography implementations. You can look for:

- classes `Cipher`, `Mac`, `MessageDigest`, `Signature`
- interfaces `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- functions `getInstance`, `generateKey`
- exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- classes which uses `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` packages.

Identify that all calls to getInstance use default `provider` of security services by not specifying it (it means AndroidOpenSSL aka Conscrypt). `Provider` can only be specified in `KeyStore` related code (in that situation `KeyStore` should be provided as `provider`). If other `provider` is specified it should be verified according to situation and business case (i.e. Android API version), and `provider` should be examined against potential vulnerabilities.  

Ensure that the best practices outlined in the "[Cryptography for Mobile Apps](../../../Document/0x04g-Testing-Cryptography.md)" chapter are followed. Look at [insecure and deprecated algorithms](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) and [common configuration issues](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues).

#### Dynamic Analysis

You can use @MASTG-TECH-0033 on cryptographic methods to determine input / output values such as the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from. For example, monitor the file system by using the [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) of @MASTG-TOOL-0037.




When apps need to use hashing in security sensitive scenarios, it is important to not use [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) algorithms.


## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and identify all the uses of hash related APIs, such as [`MessageDigest.getInstance`](https://developer.android.com/reference/java/security/MessageDigest#getInstance(java.lang.String)), and the algorithm being used.

## Observation

The output should contain a list of locations where hashing is being used and the respective algorithms.

## Evaluation

The test case fails if you can find [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) hashing algorithms being used in a security sensitive scenario.

## References

- [NIST - Hash Functions - Approved Algorithms](https://csrc.nist.gov/projects/hash-functions)
- [Testing Cryptography](../../../Document/0x04g-Testing-Cryptography.md)