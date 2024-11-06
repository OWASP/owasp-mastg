---
platform: android
title: Asymmetric key pair used for multiple purposes
id: MASTG-TEST-0x15-1
type: [static, dynamic]
weakness: MASWE-0012
---

## Overview

In general, ["a single key shall be used for only one purpose (e.g., encryption, integrity
authentication, key wrapping, random bit generation, or digital signatures)"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf).
In the case of asymmetric encryption, reusing the same key pair for multiple different cryptographic processes (e.g. signatures vs encryption) may weaken the security provided by those processes.

This does not apply to the cases where the same process can provide multiple services, e.g., when a single digital signature provides integrity authentication and source authentication.
Check ["NIST.SP.800-57pt1r5"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) for details.

## Steps

1. Use either @MASTG-TECH-0014 or @MASTG-TECH-0033 to identify all the instance where asymmetric cryptography is used.
You can look for uses of:
    - classes `Cipher`, `MessageDigest`, `Signature`, `KeyPair`, `KeyGenParameterSpec`
    - interfaces `PrivateKey`, `PublicKey`
    - functions `getInstance`, `generateKeyPair`
    - exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
    - classes importing `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*`

## Observation

The observation contains all the uses of each public and private keys with backtraces to know the locations of the `KeyPair` object.

## Evaluation

Reverse engineer the observed backtraces and try to determine the processes and purposes for which each `KeyPair` object is being used:

1. For each identified instance, identify the `KeyPair` objects used and how they are created or generated.

1. For each `PrivateKey` and `PublicKey` identify for which processes it is being used: signing/verification and encryption/decription.
    1. If a `KeyStore` is being used, you should check the [`KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties) that are being defined in the `KeyPair` generation.
    1. Otherwise, you need to search where the `PrivateKey` and `PublicKey` of each `KeyPair` are being used, and check if they are being used in `Cipher` or `Signature` objects.

The test case fails if the keys of a `KeyPair` is found being used for two distinct processes (i.e., signatures AND encryption).

## References

- [NIST.SP.800 - Recommendation for Key Management (part 1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
