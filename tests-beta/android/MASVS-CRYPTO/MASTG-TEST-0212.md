---
title: Use of Hardcoded Cryptographic Keys in Code
platform: android
id: MASTG-TEST-0212
type: [static]
weakness: MASWE-0014
profiles: [L1, L2]
---

## Overview

In this test case, we will look for the use of hardcoded keys in Android applications. To do this, we need to focus on the cryptographic implementations of hardcoded keys. The Java Cryptography Architecture (JCA) provides the [`SecretKeySpec`](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec) class, which allows you to create a [`SecretKey`](https://developer.android.com/reference/javax/crypto/SecretKey) from a byte array.

## Steps

1. Use either @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 or @MASTG-TECH-0033 (dynamic analysis) with a tool like @MASTG-TOOL-0001 to identify all the instances of symmetric key encryption in code and look for uses of the hardcoded cryptographic keys.

## Observation

The output should contain a list of locations where hardcoded keys are used.

## Evaluation

The test case fails if you find any hardcoded keys that are used in security-sensitive contexts.
