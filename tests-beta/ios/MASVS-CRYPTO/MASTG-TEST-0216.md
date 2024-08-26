---
title: Use of Hardcoded Cryptographic Keys in APIs
platform: ios
id: MASTG-TEST-0216
type: [static]
weakness: MASWE-0014
---

## Overview

In this test case, we will examine iOS applications for the presence of hardcoded cryptographic keys. Hardcoded keys can be typically found in calls to cryptographic functions or stored as constants or variables within the code. In iOS, cryptographic keys are often used in the following frameworks:

- **Security Framework**: The [`SecKeyCreateWithData`](https://developer.apple.com/documentation/security/2977516-seckeycreatewithdata) function allows developers to create a cryptographic key from raw data. If developers hardcode this data within the app, it results in hardcoded cryptographic keys.
- **CommonCrypto**: The [`CCCrypt`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html) function is often used for symmetric encryption in iOS. Developers might mistakenly hardcode symmetric keys (like AES keys) in the app's source code.
- **CryptoKit**: Although `CryptoKit` provides higher-level abstractions for cryptographic operations, developers might still hardcode private keys or other sensitive data when using the [`P256.Signing.PrivateKey`](https://developer.apple.com/documentation/cryptokit/p256/signing/privatekey) or similar classes.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary looking for cryptographic APIs as indicated above.

## Observation

The output should include any instances where potential cryptographic keys are found hardcoded within the app binary.

## Evaluation

The test fails if hardcoded cryptographic keys are found within the app binary.

You may find the keys being directly passed as arguments to cryptographic functions (byte arrays or string literals) or stored in variables or constants within the code. Typical representations of hardcoded keys include:

- **Raw Byte Arrays**: Cryptographic keys may be directly embedded in the code as arrays of `UInt8` or `Data` objects. For example, a 256-bit AES key might be represented as a `[UInt8]` array.
- **Base64-Encoded Strings**: Developers might encode cryptographic keys as Base64 strings within the code, which can be easily decoded by attackers if discovered.
- **Hex-Encoded Strings**: Keys are sometimes stored as hexadecimal strings, which are then converted to `Data` objects at runtime for cryptographic operations.

Ensure that any identified keys are indeed cryptographic keys used for security-relevant purposes. Avoid false positives by verifying the key's usage context (e.g., configuration settings or non-security-related constants might be misidentified as cryptographic keys).
