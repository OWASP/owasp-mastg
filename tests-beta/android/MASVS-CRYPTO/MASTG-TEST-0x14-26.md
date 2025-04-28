---
platform: android
title: Improper Verification of Cryptographic Signature
id: MASTG-TEST-0x14-26
type: [static, dynamic]
weakness: MASWE-0026
---

## Overview

The use of secure algorithms for cryptographic signature verification is essential to make sure an attacker did not tamper with the integrity and authenticity of the data.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and identify all the uses of Signature APIs, such as [`Signature.getInstance`](https://developer.android.com/reference/java/security/Signature#getInstance(java.lang.String)), or [`Signature.getInstance`](https://developer.android.com/reference/java/security/Signature#initVerify(java.security.PublicKey)), and the algorithm being used.

## Observation

The output should contain a list of locations where `Signature` is being used, the respective algorithms, and the cryptographic task for which it is being used.

## Evaluation

The test case fails if you can find [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) 
`Signature` algorithms being used to verify the digital signature of a piece of data used in a security sensitive scenario.

More information is provided in [NIST - Digital Signatures](https://csrc.nist.gov/projects/digital-signatures).
