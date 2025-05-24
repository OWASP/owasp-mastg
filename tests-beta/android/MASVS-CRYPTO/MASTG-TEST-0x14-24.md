---
platform: android
title: Weak Message Authentication Codes (MAC) Algorithms
id: MASTG-TEST-0x14-24
type: [static, dynamic]
weakness: MASWE-0024	
---

## Overview

Using a weak Weak Message Authentication Codes (`MAC`) algorithm in a security sensitive scenario will allow an attacker to affect the integrity and authenticity of the transmitted data.

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary, or use @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001, and identify all the uses of MAC related APIs, such as [`Mac.getInstance`](https://developer.android.com/reference/javax/crypto/Mac#getInstance(java.lang.String)), and the algorithm being used.

## Observation

The output should contain a list of locations where `MAC` is being used and the respective algorithms.

## Evaluation

The test case fails if you can find [insecure or deprecated](../../../Document/0x04g-Testing-Cryptography.md#Identifying-Insecure-and/or-Deprecated-Cryptographic-Algorithms) MAC algorithms being used in a security sensitive scenario.
A list of approved algorithms is provided in [NIST - Hash Functions](https://csrc.nist.gov/projects/hash-functions).
