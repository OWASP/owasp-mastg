---
title: Use of Hardcoded Cryptographic Keys in Code
platform: ios
id: MASTG-TEST-0213
type: [static]
weakness: MASWE-0014
profiles: [L1, L2]
---

## Overview

In this test case, we will examine iOS applications for the presence of hardcoded cryptographic keys. Hardcoded keys can be typically found in calls to cryptographic functions or stored as constants or variables within the code. In iOS, cryptographic keys are often used in the following frameworks:

- **Security Framework**: The [`SecKeyCreateWithData`](https://developer.apple.com/documentation/security/seckeycreatewithdata(_:_:_:)) function allows developers to create a cryptographic key from raw data.
- **CommonCrypto**: The [`CCCrypt`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html) can be initialized with raw key data in its `key` parameter.
- **CryptoKit**: Although `CryptoKit` provides higher-level abstractions for cryptographic operations, developers might still hardcode cryptographic keys in different formats and feed it to methods like [`P256.Signing.PrivateKey.init(rawRepresentation:)`](https://developer.apple.com/documentation/cryptokit/p256/signing/privatekey/init(rawrepresentation:)) or similar.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary looking for cryptographic APIs as indicated above.

## Observation

The output should include any instances where the app uses cryptographic functions that accept raw key data. Whenever possible, the output should also try to point to the raw key data from the binary.

## Evaluation

The test fails if calls to cryptographic functions with hardcoded keys are found within binary.

You may find the keys being directly passed as arguments to cryptographic functions (byte arrays or string literals) or stored in variables or constants within the code. Typical representations of hardcoded keys include:

- **Raw Byte Arrays**: Cryptographic keys may be directly embedded in the code as arrays of `UInt8` or `Data` objects. For example, a 256-bit AES key might be represented as a `[UInt8]` array.
- **Base64-Encoded Strings**: Developers might encode cryptographic keys as Base64 strings within the code, which can be easily decoded by attackers if discovered.
- **Hex-Encoded Strings**: Keys are sometimes stored as hexadecimal strings, which are then converted to `Data` objects at runtime for cryptographic operations.

Ensure that any identified keys are indeed cryptographic keys used for security-relevant purposes. Avoid false positives by verifying the key's usage context (e.g., configuration settings or non-security-related constants might be misidentified as cryptographic keys).
