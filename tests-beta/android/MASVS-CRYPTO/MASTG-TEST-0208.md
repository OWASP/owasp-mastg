---
platform: android
title: Inappropriate Key Sizes 
id: MASTG-TEST-0208
type: [static]
weakness: MASWE-0009
---

## Overview

In this test case, we will look for the use inappropriate key sizes in Android apps. To do this, we need to focus on the cryptographic frameworks and libraries that are available in Android and the methods that are used to generate cryptographic keys.

In Android the class `KeyGenerator` is able to create keys for different [encryption algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyGenerator). 

There are a variety of different [KeyGenerator.init()](https://developer.android.com/reference/javax/crypto/KeyGenerator#public-methods) methods to initialise the key generation, where some require random bytes. The entropy of these random bytes will rely on the `SecureRandom` implementation in the available security provider, otherwise a system-provided source of randomness will be used.

During the key generation you can select outdated encryption algorithms or insufficient key lengths and this is what we'll focus on in this test.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the cryptographic functions that generate keys.

## Observation

The output should contain a list of locations where insufficient key lengths are used.

## Evaluation

The test case fails if you can find the use of inappropriate key sizes within the source code. For example, a 1024-bit key size is considered weak for RSA encryption and a 128-bit key size is considered weak for AES encryption considering quantum computing attacks.
