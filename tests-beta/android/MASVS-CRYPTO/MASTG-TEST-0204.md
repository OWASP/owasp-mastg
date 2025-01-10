---
platform: android
title: Insecure Random API Usage
id: MASTG-TEST-0204
type: [static]
best-practices: [MASTG-BEST-0001]
prerequisites:
- identify-sensitive-data
- identify-security-relevant-contexts
weakness: MASWE-0027
---

## Overview

Android apps sometimes use an insecure [pseudorandom number generator (PRNG)](../../../Document/0x05e-Testing-Cryptography.md#random-number-generation) such as [`java.util.Random`](https://developer.android.com/reference/java/util/Random), which is essentially a linear congruential generator. This type of PRNG generates a predictable sequence of numbers for any given seed value, making the sequence reproducible and insecure for cryptographic use. In particular, `java.util.Random` and `Math.random()` ([the latter](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/) simply calling `nextDouble()` on a static `java.util.Random` instance) produces identical number sequences when initialized with the same seed across all Java implementations.
In general, if a PRNG is not advertised as being cryptographically secure, then it is probably a statistical PRNG and should not be used in security-sensitive contexts.
See the [Android Documentation](https://developer.android.com/privacy-and-security/risks/weak-prng) and the guide on ["random number generation"](../../../Document/0x05e-Testing-Cryptography.md#random-number-generation) for details.

## Steps

1. Run a static analysis (@MASTG-TECH-0014) tool on the app and look for insecure random APIs, or you can use @MASTG-TECH-0033 to detect the use of such APIs.
2. For each of the identified API uses, check if they are used in a security relevant context.
For this, you can reverse engineer the app (@MASTG-TECH-0017) and inspect the code(@MASTG-TECH-0023).

## Observation

The output should contain a list of locations where insecure random APIs are used.

## Evaluation

The test case fails if you can find random numbers generated using those APIs that are used in security-relevant contexts, such as generating passwords or authentication tokens.
