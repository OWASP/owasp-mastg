---
platform: android
title: Weak Signature Algorithms
id: MASTG-TEST-0x14-25
type: [static, dynamic]
weakness: MASWE-0025	
---

## Overview

The use of secure cryptographic algorithms to digitally sign data in a security sensitive context is essential to prevent that attackers did not tamper with the integrity and authenticity of the data.


## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and identify all the uses of Signature APIs, such as [`Signature.getInstance`](https://developer.android.com/reference/java/security/Signature#getInstance(java.lang.String)), or [`Signature.getInstance`](https://developer.android.com/reference/java/security/Signature#initSign(java.security.PrivateKey,%20java.security.SecureRandom)), and the algorithm being used.

## Observation

The output should contain a list of locations where `Signature` is being used and the respective algorithms.

## Evaluation

The test case fails if you can find [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) 
`Signature` algorithms being used to create the digital signature of a piece of data used in a security sensitive scenario.

More information is provided in [NIST - Digital Signatures](https://csrc.nist.gov/projects/digital-signatures).
