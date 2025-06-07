---
title: Usage of Insecure Signature Key Size
platform: android
id: MASTG-TEST-0225
type: [static]
weakness: MASWE-0104
profiles: [R]
---

## Overview

For Android apps, the cryptographic strength of the APK signature is essential for maintaining the app's integrity and authenticity. Using a signature key with insufficient length, such as an RSA key shorter than 2048 bits, weakens security, making it easier for attackers to compromise the signature. This vulnerability could allow malicious actors to forge signatures, tamper with the app's code, or distribute unauthorized, modified versions.

## Steps

1. List the additional signature information using @MASTG-TECH-0116.

## Observation

The output should contain the information about the key size in a line like: `Signer #1 key size (bits):`.

## Evaluation

The test case fails if any of the key sizes (in bits) is less than 2048 (RSA). For example, `Signer #1 key size (bits): 1024`.
