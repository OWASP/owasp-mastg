---
title: Weak Encryption Algorithms
platform: android
id: MASTG-TEST-0211
type: [static]
weakness: MASWE-0020
---

## Overview

In this test case, we will look for the use of weak encryption in Android. To do this, we need to focus on the cryptographic algorithms and encryption modes that are available in Android. The Java Cryptography Architecture (JCA) provides a framework for secure cryptographic operations, but improper implementation can lead to security vulnerabilities. Particularly, the use of outdated algorithms and modes can compromise data security despite using the JCA framework.

Weak encryption methods pose significant security risks in modern applications. [DES (Data Encryption Standard) and 3DES (Triple DES)](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm),  are vulnerable to brute force attacks using current computing technology. These algorithms, once considered secure, are now deprecated by NIST and should be replaced with stronger alternatives like [AES-256](https://developer.android.com/privacy-and-security/cryptography#choose-algorithm).

Encryption modes also play a crucial role in security. The [Electronic Codebook (ECB) mode](https://support.google.com/faqs/answer/10046138?hl=en), which encrypts each block independently, is particularly problematic as it reveals patterns in the encrypted data. This weakness is especially concerning in Android development, where `Cipher.getInstance("AES")` defaults to [ECB mode](https://support.google.com/faqs/answer/10046138?hl=en) if no mode is specified, potentially leading to insecure implementations.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the hardcoded cryptographic keys.

## Observation

The output should contain a list of locations where insecure encryption are used.

## Evaluation

The test case fails if you find any insecure encryption.
