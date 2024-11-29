---
title: Weak Encryption Modes
platform: android
id: MASTG-TEST-0222
type: [static, dynamic]
weakness: MASWE-0020
---

## Overview

To test for the [use of weak encryption modes](../../../Document/0x04g-Testing-Cryptography.md#weak-block-cipher-mode) in Android apps, we need to focus on methods from cryptographic frameworks and libraries that are used to configure and apply encryption modes.

In Android development, the `Cipher` class from the Java Cryptography Architecture (JCA) is the primary API that allows you to specify the encryption mode for cryptographic operations. [`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)) defines the transformation string, which includes the encryption algorithm, mode of operation, and padding scheme. The general format is `"Algorithm/Mode/Padding"`. For example:

```java
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
```

In this test we're going to focus on symmetric encryption modes such as [ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)) operate deterministically, dividing plaintext into blocks and encrypting them separately, which reveals patterns in the ciphertext. This makes it vulnerable to attacks like [known-plaintext attacks](https://en.wikipedia.org/wiki/Known-plaintext_attack) and [chosen-plaintext attacks](https://en.wikipedia.org/wiki/Chosen-plaintext_attack).

**Out of Scope**: Asymmetric encryption modes like RSA are out of scope for this test because they don't use block modes like ECB.

In the transformation strings like `"RSA/ECB/OAEPPadding"` or "RSA/ECB/PKCS1Padding", the inclusion of "ECB" in this context is misleading. Unlike symmetric ciphers, **RSA doesn't operate in block modes like ECB**. The "ECB" designation is a [placeholder in some cryptographic APIs](https://github.com/openjdk/jdk/blob/680ac2cebecf93e5924a441a5de6918cd7adf118/src/java.base/share/classes/com/sun/crypto/provider/RSACipher.java#L126) and doesn't imply that RSA uses ECB mode. Understanding these nuances helps prevent false positives.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and look for cryptographic functions specifying the encryption mode to insecure modes.

## Observation

The output should contain a list of locations where insecure or deprecated encryption modes are used in cryptographic operations.

## Evaluation

The test case fails if any insecure encryption modes are identified in the app.

Replace insecure encryption modes with secure block cipher modes such as [AES-GCM or AES-CCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) which are authenticated encryption modes that provide confidentiality, integrity, and authenticity.

We recommend to avoid CBC, which while being more secure than ECB, improper implementation, especially incorrect padding, can lead to vulnerabilities such as padding oracle attacks.

For comprehensive guidance on implementing secure encryption modes in Android, refer to the official Android Developers documentation on [Cryptography](https://developer.android.com/privacy-and-security/cryptography).
