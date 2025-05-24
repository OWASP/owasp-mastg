---
platform: android
title: Weak Hashing Algorithms
id: MASTG-TEST-0x14-1
type: [static, dynamic]
weakness: MASWE-0021
---

## Overview

When apps need to use hashing in security sensitive scenarios, it is important to not use [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) algorithms.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and identify all the uses of hash related APIs, such as [`MessageDigest.getInstance`](https://developer.android.com/reference/java/security/MessageDigest#getInstance(java.lang.String)), and the algorithm being used.

## Observation

The output should contain a list of locations where hashing is being used and the respective algorithms.

## Evaluation

The test case fails if you can find [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) hashing algorithms being used in a security sensitive scenario.
A list of approved algorithms is provided in [NIST - Hash Functions](https://csrc.nist.gov/projects/hash-functions).
