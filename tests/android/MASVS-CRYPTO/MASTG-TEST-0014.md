---
masvs_v1_id:
- MSTG-CRYPTO-2
- MSTG-CRYPTO-3
- MSTG-CRYPTO-4
masvs_v2_id:
- MASVS-CRYPTO-1
platform: android
title: Testing the Configuration of Cryptographic Standard Algorithms
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

## Static Analysis

Identify all the instances of the cryptographic primitives in code. Identify all custom cryptography implementations. You can look for:

- classes `Cipher`, `Mac`, `MessageDigest`, `Signature`
- interfaces `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
- functions `getInstance`, `generateKey`
- exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
- classes which uses `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` packages.

Identify that all calls to getInstance use default `provider` of security services by not specifying it (it means AndroidOpenSSL aka Conscrypt). `Provider` can only be specified in `KeyStore` related code (in that situation `KeyStore` should be provided as `provider`). If other `provider` is specified it should be verified according to situation and business case (i.e. Android API version), and `provider` should be examined against potential vulnerabilities.

Ensure that the best practices outlined in the "[Cryptography for Mobile Apps](../../../Document/0x04g-Testing-Cryptography.md)" chapter are followed. Look at [insecure and deprecated algorithms](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) and [common configuration issues](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues).

## Dynamic Analysis

You can use @MASTG-TECH-0033 on cryptographic methods to determine input / output values such as the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from. For example, monitor the file system by using the [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) of @MASTG-TOOL-0037.
