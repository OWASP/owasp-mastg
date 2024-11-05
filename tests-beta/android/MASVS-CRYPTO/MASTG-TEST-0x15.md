---
platform: android
title: Testing the Purposes of Keys
id: MASTG-TEST-0x15
type: [static, dynamic]
weakness: MASWE-0012
---

## Overview

In general, ["a single key shall be used for only one purpose (e.g., encryption, integrity
authentication, key wrapping, random bit generation, or digital signatures)"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf).
Reusing the same key or key pair for multiple purposes may weaken its security or increase the impact of one key being compromised.

This does not apply to the cases where the same process can provide
multiple services, e.g., when a single digital signature provides integrity
authentication and source authentication.
Check ["NIST.SP.800-57pt1r5"](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) for details.

## Steps

1. Use either @MASTG-TECH-0014 or @MASTG-TECH-0033 to identify all the where cryptography is used.
You can look for uses of:
    - classes `Cipher`, `Mac`, `MessageDigest`, `Signature`, `KeyPair`
    - interfaces `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
    - functions `getInstance`, `generateKey`, `generateKeyPair`
    - exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
    - classes importing `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*`

2. For each identified instance, identify its purpose and its type. It can be used:
    - for encryption/decryption - to ensure data confidentiality
    - for signing/verifying - to ensure integrity of data (as well as accountability in some cases)
    - for maintenance - to protect keys during certain sensitive operations (such as being imported to the KeyStore)

3. Identify the business logic which uses identified instances of cryptography.

4. During verification the following checks should be performed:
    - are all keys used according to the purpose defined during its creation? (it is relevant to KeyStore keys, which can have KeyProperties defined)
    - for asymmetric keys, is the private key being exclusively used for signing and the public key encryption?
    - are symmetric keys used for multiple purposes? A new symmetric key should be generated if it's used in a different context.
    - is cryptography used according to its business purpose?

## Observation

The output should contain a list of location groups where a key or key pair is being used for multiple cryptographic purposes.
The output should contain a list of location groups where a key or key pair is being used for multiple business purposes.

- are all keys used according to the purpose defined during its creation? (it is relevant to KeyStore keys, which can have KeyProperties defined)
- for asymmetric keys, is the private key being exclusively used for signing and the public key encryption?
- are symmetric keys used for multiple purposes? A new symmetric key should be generated if it's used in a different context.
- is cryptography used according to its business purpose?

## Evaluation

The test case fails if (lists before are not empty. TBC after discussion).

## References

- [NIST.SP.800 - Recommendation for Key Management (part 1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
