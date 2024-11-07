---
platform: android
title: Weak Padding
id: MASTG-TEST-0x14-23
type: [static, dynamic]
weakness: MASWE-0023
---

## Overview

The cipher padding used in a security sensitive context should be carefully selected, otherwise it can be used to compromise the confidentiality, integrity and authenticity of the encrypted data.

In the case of symmetric block ciphers, a secure padding scheme is used to prevent that the last block is not filled data that could be exploited by the adversary.
In the case of assymetric encryption (e.g., `RSA`), padding scheme is required to prevent deterministic encryption, i.e., that a specific plaintext always results in the same ciphertext.

Check the [documentation on attacks agains padding](../../../Document/0x04g-Testing-Cryptography.md#Padding-Oracle-Attacks-due-to-Weaker-Padding-or-Block-Operation-Implementations) for more complete examples.

There are exceptions to this, as is the case of the [android recommended cipher](https://developer.android.com/privacy-and-security/cryptography#choose-algorithm) `AES/GCM/NoPadding`, in which `GCM` mode uses part of the authentication tag as padding for the blocs.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and identify all the uses of encryption related APIs, such as [`Cipher.getInstance`](https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)), and the first argument (`transformation`) being used.

## Observation

The output should contain a list of locations where a `Cipher` is being created and the text of the respective `transformation`.

## Evaluation

The test case fails if you can find at least one `Cipher` defined with a `transformation` whose [padding scheme is not adequate](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) to the algorithm and mode, and such `Cipher` is used in a security sensitive context.

- If you are using `RSA` algorithm, you are required to use `OAEPPadding` (or one of its versions);
- Otherwise, weak padding such as NoPadding, ZeroPadding, etc. should be avoided unless you are sure that is secure for that specific combination (e.g., as is the case for `AES/GCM/NoPadding`).

Check the documentation for [specific recomendation on padding schemes to use](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms).

## References

- [Testing Cryptography](../../../Document/0x04g-Testing-Cryptography.md)
- [Cryptographic Mechanisms: Recommendations and Key Lengths](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile)
