---
title: Use of Hardcoded Cryptographic Keys in Code
platform: android
id: MASTG-TEST-0210
type: [static]
weakness: MASWE-0014
---

## Overview

In this test case, we will look for the use of hardcoded keys in android applications. To do this, we need to focus on the cryptographic implementations of hardcoded keys. The Java Cryptography Architecture (JCA) provides SecretKeySpec class which allows you to create a secret key from a byte array.

[SecretKeySpec](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec)
For more information, you can consult the MASTG section about [Static Analysis](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/#overview)

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the hardcoded cryptographic keys.

## Observation

The output should contain a list of locations where hardcoded keys are getting used.

## Evaluation

The test case fails if you can find the hardcoded key is just stored and not used by the application
