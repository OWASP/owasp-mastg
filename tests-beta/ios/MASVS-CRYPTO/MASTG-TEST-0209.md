---
platform: ios
title: Insufficient Key Sizes
id: MASTG-TEST-0209
type: [static, dynamic]
weakness: MASWE-0009
profiles: [L1, L2]
---

## Overview

In this test case, we will look for the use insufficient key sizes in iOS apps. To do this, we need to focus on the cryptographic frameworks and libraries that are available in iOS and the methods that are used to generate cryptographic keys.

- **CommonCrypto**: The [`CCCrypt`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html) function is used for symmetric encryption and decryption and specifies the key size or key length in its fifth parameter `keyLength`.
- **Security**: The [`SecKeyCreateRandomKey`](https://developer.apple.com/documentation/security/1823694-seckeycreaterandomkey) function is used to generate a random key using certain attributes including [`kSecAttrKeyType`](https://developer.apple.com/documentation/security/ksecattrkeytype) and [`kSecAttrKeySizeInBits`](https://developer.apple.com/documentation/security/ksecattrkeysizeinbits). The [`SecKeyGeneratePair`](https://developer.apple.com/documentation/security/1395339-seckeygeneratepair) function is deprecated in iOS 16.
- **CryptoKit**: The [`AES.GCM`](https://developer.apple.com/documentation/cryptokit/aes/gcm) and [`ChaChaPoly`](https://developer.apple.com/documentation/cryptokit/chachapoly) classes are used for symmetric encryption and decryption.

Since you don't usually generate keys directly in CryptoKit (the library does that for you automatically), we'll focus on the CommonCrypto and Security libraries in this test.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary, or use a dynamic analysis tool like @MASTG-TOOL-0039, and look for uses of the cryptographic functions that generate keys.

## Observation

The output should contain the disassembled code of the functions using `CCCrypt` or other cryptographic functions.

## Evaluation

The test case fails if you can find the use of insufficient key sizes within the source code. For example, a 1024-bit key size is considered insufficient for RSA encryption and a 128-bit key size is considered insufficient for AES encryption considering quantum computing attacks.
