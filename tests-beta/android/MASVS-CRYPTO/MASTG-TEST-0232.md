---
title: Broken Symmetric Encryption Modes
platform: android
id: MASTG-TEST-0232
type: [static, dynamic]
weakness: MASWE-0020
best-practices: [MASTG-BEST-0005]
profiles: [L1, L2]
---

## Overview

To test for the [use of broken encryption modes](../../../Document/0x04g-Testing-Cryptography.md#broken-block-cipher-modes) in Android apps, we need to focus on methods from cryptographic frameworks and libraries that are used to configure and apply encryption modes.

In Android development, the `Cipher` class from the Java Cryptography Architecture (JCA) is the primary API that allows you to specify the encryption mode for cryptographic operations. [`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)) defines the transformation string, which includes the encryption algorithm, mode of operation, and padding scheme. The general format is `"Algorithm/Mode/Padding"`. For example:

```kotlin
Cipher.getInstance("AES/ECB/PKCS5Padding")
```

In this test we're going to focus on symmetric encryption modes such as [ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)).

ECB (defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final)) is generally discouraged [see NIST announcement in 2023](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a) due to its inherent security weaknesses. While not explicitly prohibited, its use is limited and advised against in most scenarios. ECB is a block cipher mode that operate deterministically, dividing plaintext into blocks and encrypting them separately, which reveals patterns in the ciphertext. This makes it vulnerable to attacks like [known-plaintext attacks](https://en.wikipedia.org/wiki/Known-plaintext_attack) and [chosen-plaintext attacks](https://en.wikipedia.org/wiki/Chosen-plaintext_attack).

For example, the following transformations are all [considered vulnerable](https://support.google.com/faqs/answer/10046138?hl=en):

- `"AES"` (uses AES/ECB mode by [default](https://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher))
- `"AES/ECB/NoPadding"`
- `"AES/ECB/PKCS5Padding"`
- `"AES/ECB/ISO10126Padding"`

You can learn more about ECB and other modes in [NIST SP 800-38A - Recommendation for Block Cipher Modes of Operation: Methods and Techniques](https://csrc.nist.gov/pubs/sp/800/38/a/final). Also check the [Decision to Revise NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation: Methods and Techniques](https://csrc.nist.gov/news/2023/decision-to-revise-nist-sp-800-38a) and [NIST IR 8459 Report on the Block Cipher Modes of Operation in the NIST SP 800-38 Series](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8459.pdf) for the latest information.

**Out of Scope**: Asymmetric encryption modes like RSA are out of scope for this test because they don't use block modes like ECB.

In the transformation strings like `"RSA/ECB/OAEPPadding"` or `"RSA/ECB/PKCS1Padding"`, the inclusion of `ECB` in this context is misleading. Unlike symmetric ciphers, **RSA doesn't operate in block modes like ECB**. The `ECB` designation is a [placeholder in some cryptographic APIs](https://github.com/openjdk/jdk/blob/680ac2cebecf93e5924a441a5de6918cd7adf118/src/java.base/share/classes/com/sun/crypto/provider/RSACipher.java#L126) and doesn't imply that RSA uses ECB mode. Understanding these nuances helps prevent false positives.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and look for cryptographic functions specifying the encryption mode to insecure modes.

## Observation

The output should contain a list of locations where broken encryption modes are used in cryptographic operations.

## Evaluation

The test case fails if any broken modes are identified in the app.
