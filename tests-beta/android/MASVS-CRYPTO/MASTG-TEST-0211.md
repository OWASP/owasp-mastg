---
title: Weak Encryption Algorithms
platform: android
id: MASTG-TEST-0211
type: [static]
weakness: MASWE-0020
---

## Overview

In this test case, we will look for the use of weak encryption in Android applications. To do this, we need to focus on the cryptographic implementations of algorithm such as DES, 3DES,Weak encryption modes (e.g. ECB) and Cipher.getInstance("AES") defaults to ECB.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the hardcoded cryptographic keys.

## Observation

The output should contain a list of locations where insecure encryption are used.

## Evaluation

The test case fails if you find any insecure encryption.
